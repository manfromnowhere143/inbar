# Iteration 001 Terminal Authority V1

Status: implementation design; canonical authority remains bootstrap

Decision date: 2026-07-15

Decision: `BLOCK_PUBLICATION_PENDING_TERMINAL_AUTHORITY`

## Problem

The current admission report binds several inputs but omits other verdict-bearing artifacts,
including the shortcut report and protocol reviews. Its output manifest hashes the report and
rendered result, but the three files can be rewritten together because no terminal signature exists.
Failures that occur before report construction exit without the preregistered reconstructible
`INVALID` artifact.

Atomic directory publication prevents partial writes and accidental overwrite. It does not provide
authenticity, completeness, or replay authority.

## Authority separation

Terminal admission uses a dedicated Ed25519 verifier key. It is not a source, evidence curator,
mechanism, safety, execution, outcome, or statistician key.

The governance root issues a committed verifier certificate containing:

```python
class AdmissionVerifierCertificate(FrozenModel):
    schema_version: Literal["fieldtrue.admission-verifier-certificate.v1"]
    certificate_id: Identifier
    iteration_id: Literal["iter001_physical_causal_evidence_acquisition"]
    verifier_id: Identifier
    verifier_public_key: Ed25519PublicKey
    validator_git_blob: GitObjectId
    validator_source_sha256: Sha256
    control_suite_sha256: Sha256
    dependency_lock_sha256: Sha256
    not_before: datetime
    expires_at: datetime
    root_attestation: SignedAttestation
```

The private verifier key remains under `.local/keys`, is never logged or committed, and is loaded
only after validation, input re-snapshot, and output staging succeed. The root key does not sign
terminal results directly.

Canonical verification requires `control_authority_status=sealed`, an exact committed certificate,
a clean committed HEAD, the frozen validator Git blob, and the verified production control bundle.

## Complete input snapshot

Before audit, enumerate every regular file below the resolved acquisition root without following
symlinks. Reject devices, sockets, hard links outside the root, path aliases, case-fold collisions,
non-normalized names, files that change while hashing, and any output path within the input.

```python
class AcquisitionInputEntry(FrozenModel):
    path: str
    sha256: Sha256
    bytes: int
    mode: int

class AcquisitionInputManifest(FrozenModel):
    schema_version: Literal["fieldtrue.acquisition-input-manifest.v1"]
    iteration_id: Literal["iter001_physical_causal_evidence_acquisition"]
    root_algorithm: Literal["sha256-canonical-path-content-v1"]
    entries: tuple[AcquisitionInputEntry, ...]
    total_bytes: int
    root_sha256: Sha256
```

Entries use canonical UTF-8 byte ordering. `root_sha256` hashes the complete canonical entry tuple,
not filesystem traversal order. Snapshot the input again after audit and immediately before signing.
Any difference yields `INVALID_INPUT_MUTATION`; it never produces a stale report.

The complete input root is the umbrella authority. The typed report also retains explicit hashes
for contract, trust registry, control suite, candidate registry, source manifests, protocol reviews,
shortcut registry and evaluations, comparator registry, split locks, eligible dossier corpus,
resource usage, and the validator.

## Terminal payloads

Successful and blocked scientific audits use the existing typed admission report after adding the
complete input-manifest hash and all explicit verdict-bearing registry hashes.

Pre-report failures use a narrow typed record:

```python
class AdmissionInvalidityRecord(FrozenModel):
    schema_version: Literal["fieldtrue.admission-invalidity-record.v1"]
    iteration_id: Literal["iter001_physical_causal_evidence_acquisition"]
    contract_sha256: Sha256
    input_manifest_sha256: Sha256
    failure_stage: Literal[
        "authority",
        "input_snapshot",
        "control_verification",
        "artifact_loading",
        "admission_audit",
        "output_staging",
    ]
    failure_code: Identifier
    diagnostic_sha256: Sha256
    occurred_at: datetime
```

`diagnostic_sha256` binds a local diagnostic artifact without making free-form error text part of
the verdict. The public record exposes only stable failure codes. Stack traces, paths outside the
mission root, environment values, and key material are forbidden.

If even the canonical contract or verifier certificate cannot be authenticated, the CLI may write
an unsigned local diagnostic but must not label it a terminal scientific artifact. A signed
`INVALID` requires a valid mission root, verifier certificate, and reproducible input snapshot.

## Terminal record

```python
class AdmissionTerminalRecord(FrozenModel):
    schema_version: Literal["fieldtrue.admission-terminal-record.v1"]
    terminal_id: Identifier
    iteration_id: Literal["iter001_physical_causal_evidence_acquisition"]
    execution_commit: GitObjectId
    execution_tree: GitObjectId
    contract_sha256: Sha256
    verifier_certificate_sha256: Sha256
    control_suite_sha256: Sha256
    validator_git_blob: GitObjectId
    validator_source_sha256: Sha256
    dependency_lock_sha256: Sha256
    input_manifest: ArtifactBinding
    payload_kind: Literal["admission_report", "invalidity_record"]
    payload: ArtifactBinding
    rendered_result: ArtifactBinding
    produced_at: datetime
    verifier_id: Identifier
    verifier_public_key: Ed25519PublicKey
    attestation_hash: Sha256
    signature: Ed25519Signature
```

The signature covers the canonical terminal body without `attestation_hash` and `signature`.
`attestation_hash` is the canonical-body hash. All output bindings name immutable files inside the
single-use output directory.

## Generation algorithm

1. Resolve repository, input, and output roots and enforce disjointness.
2. Verify canonical contract bytes at committed HEAD.
3. Verify sealed control authority, verifier certificate, validator Git blob, dependency lock, and
   clean execution commit and tree.
4. Create the first complete input snapshot.
5. Run admission through the production validator path.
6. Convert a classified audit failure into an invalidity record when terminal authority remains
   valid.
7. Re-snapshot the input and require byte equality with the first snapshot.
8. Stage input manifest, typed payload, and deterministic ASCII result in a new temporary directory.
9. Recheck clean HEAD, execution tree, bound Git blobs, dependency lock, certificate, and input
   snapshot.
10. Load the verifier key, require its public key to equal the certificate, sign the terminal body,
    zero key buffers where the runtime permits, and write the terminal record.
11. Fsync every file and directory, atomically rename the staging directory, and never merge or
    overwrite an existing output.

No network, cloud, GPU, live-system, or external command authority is required.

## Read-only verification

`verify_admission_terminal(repo, input_root, output_root)` performs all checks without a private key:

1. Parse every typed artifact with extra fields forbidden.
2. Verify the root-signed verifier certificate and terminal signature.
3. Verify committed execution ancestry, exact tree, validator blob, source hash, dependency lock,
   and control-suite receipt.
4. Rebuild the complete input manifest and require the exact root and entry tuple.
5. Verify every output artifact binding and reject extra or missing output files.
6. Rerun the validator from the bound implementation.
7. For an admission report, require byte-exact canonical equality with rerun output and exact
   deterministic rendering.
8. For an invalidity record, require the rerun to fail at the same stable stage and code.

Verification returns a typed result and never repairs, replaces, or re-signs output.

## Required controls

Terminal authority must reject at least:

- coordinated replacement of report, result, and old manifest;
- replacement of shortcut or protocol-review input without changing the report;
- one omitted or extra input file;
- file content, size, mode, path, or case changed after the first snapshot;
- symlink, device, socket, or root-escape input;
- output nested below input;
- verifier key different from its root certificate;
- certificate with wrong validator, controls, lock, validity window, or root signature;
- dirty HEAD or correct commit with a different working tree;
- terminal signature over noncanonical bytes;
- extra output file or missing bound file;
- admission report that differs from replay by one field;
- invalidity record with a changed stage or code;
- arbitrary exception text presented as a stable failure code;
- private-key or environment material in diagnostics; and
- attempt to overwrite an existing output directory.

Positive controls must include one canonical blocked result and one reproducible signed invalidity
result. A canonical `PASS_PILOT` control is added only after all scientific and shortcut gates can
honestly pass.

## Research-engine extraction

The later research engine should treat a terminal result as a signed function of five authorities:
the prospective contract, exact code and dependencies, executable control receipt, complete input
snapshot, and deterministic payload. Atomic writing is durability. A signature plus replay is
authority. Neither substitutes for the other.
