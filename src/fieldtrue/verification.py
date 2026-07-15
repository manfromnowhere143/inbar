"""Independent verification for the frozen iteration 000 proof bundle."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from collections.abc import Mapping
from copy import deepcopy
from datetime import UTC, datetime
from itertools import pairwise
from pathlib import Path
from typing import Any, Literal, NoReturn, TypeVar, cast

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey
from pydantic import BaseModel, ConfigDict, ValidationError

from fieldtrue.adapters.adapt import (
    AdaptCoverageReport,
    AdaptDatasetLock,
    AdaptIngestionReceipt,
)
from fieldtrue.canonical import (
    atomic_write,
    canonical_json,
    canonical_json_pretty,
    sha256_bytes,
    sha256_file,
    sha256_value,
)
from fieldtrue.domain import (
    Ed25519PublicKey,
    GateStatus,
    HexSignature,
    Identifier,
    ReadinessReport,
    Sha256,
)
from fieldtrue.readiness import audit_adapt_proof_readiness, render_readiness_result
from fieldtrue.receipts import (
    LedgerEvent,
    LedgerVerification,
    LedgerVerificationError,
    SignerAnchor,
    load_or_create_signing_key,
    load_signer_anchor,
    verify_ledger,
    write_signer_anchor,
)
from fieldtrue.runtime import RuntimeIdentity, collect_runtime_identity

_ITERATION_ID = "iter000_nasa_adapt_corpus_readiness"
_ANCHOR_ID = "iter000-execution-ledger"
_HYPOTHESIS_PATH = f"experiments/{_ITERATION_ID}/HYPOTHESIS.md"
_AMENDMENT_DOCUMENT_PATH = f"experiments/{_ITERATION_ID}/AMENDMENT_001.md"
_AMENDMENT_CONTRACT_PATH = "protocol/amendments/iter000_001.json"
_AUTHORITY_PROTOCOL_PATH = "protocol/attempt_authorities/iter000_001.json"
_ANCHOR_PROTOCOL_PATH = "protocol/trust/iter000_signer_anchor.json"
_DATASET_PROTOCOL_PATH = "protocol/datasets/nasa_adapt_v1.json"
_LOCKFILE_PROTOCOL_PATH = "uv.lock"
_AUTHORITY_ARTIFACT = "attempt_authority.json"
_AUTHORITY_CONSUMPTION_ARTIFACT = "attempt_authority_consumption.json"
_AUTHORITY_RECEIPT_PATH = f"experiments/{_ITERATION_ID}/authority/attempt_001_consumption.json"
_AUTHORIZED_COMMAND = ("fieldtrue", "experiment", "iter000-amendment-001")
_CORRECTED_VERIFICATION_COMMAND = (
    "fieldtrue",
    "experiment",
    "verify-iter000-amendment-001-correction-001",
)
_CLEAN_STATE_HASH = sha256_bytes(b"")
_ATTEMPT_000_LEDGER_PATH = f"experiments/{_ITERATION_ID}/proof/attempt_000/execution_ledger.jsonl"
_ATTEMPT_000_HEAD_PATH = f"experiments/{_ITERATION_ID}/proof/attempt_000/execution_ledger.head.json"
_ATTEMPT_000_LEDGER_HASH = "c84327a7c15e48e7169711b7b84aa7167fa170ab3b735993b3ff5b224d7e5982"
_ATTEMPT_000_HEAD_FILE_HASH = "332878b131ab2c5a0c024854f0a43a552c0f8b0a36330d18a0b3b405b89bfa07"
_ATTEMPT_000_HEAD_HASH = "acf079ecb5b989d3b5615d01bed4141fbd1d9c95436baabc65cfff707ff914d9"
_ATTEMPT_000_COMMIT = "2fb078a1cac5f76f251ab49e0368ae0ea3e8da2e"
_ATTEMPT_000_FAILURE = (
    "<urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
    "unable to get local issuer certificate (_ssl.c:1000)>"
)
_ATTEMPT_001_CERTIFI_VERSION = "2026.6.17"
_ATTEMPT_001_CA_BUNDLE_SHA256 = "bbc7e9c01d7551bb8a159b5dedd989b8ee3ce105aff522b68eb1b01bf854cab0"
_ATTEMPT_001_EXECUTION_COMMIT = "ab20d41be48003c443a807c733c4c8ce43445e01"
_ATTEMPT_001_EXECUTION_TREE = "e3d8a8609e483b37c755b252e4f43b57b4731480"
_ATTEMPT_001_PROOF_COMMIT = "15cd75dd761a1c3f1d75994445a9ce702c58810a"
_ATTEMPT_001_PROOF_COMMIT_TREE = "388a78ef4afe4187dc0d2389feb28899571589fb"
_ATTEMPT_001_PROOF_PATH = f"experiments/{_ITERATION_ID}/proof/attempt_001"
_ATTEMPT_001_PROOF_SUBTREE = "5ad82ba61c522fc3e292ab7ceed9f7085b556673"
_VERIFICATION_AMENDMENT_COMMIT = "f9983e26e0e9d48c14016dfc4d897962767f8da8"
_VERIFICATION_AMENDMENT_COMMIT_TREE = "552755b74e49ab7810df2e965519f556796ba604"
_VERIFICATION_AMENDMENT_DOCUMENT_PATH = f"experiments/{_ITERATION_ID}/VERIFICATION_AMENDMENT_001.md"
_VERIFICATION_AMENDMENT_DOCUMENT_SHA256 = (
    "d472b8b594b2a278f095de50435df2dfed1e4b72a9b4b9bb53502283545c9048"
)
_VERIFICATION_AMENDMENT_PATH = "protocol/amendments/iter000_verification_001.json"
_VERIFICATION_AMENDMENT_SHA256 = "919df0feab263c52889964b728ddd296c8d585019a66fe3c01bd997fc893bfa9"
_VERIFICATION_AMENDMENT_CORRECTION_DOCUMENT_PATH = (
    f"experiments/{_ITERATION_ID}/VERIFICATION_AMENDMENT_002.md"
)
_VERIFICATION_AMENDMENT_CORRECTION_DOCUMENT_SHA256 = (
    "394815237a85354a4b8b93054dd57fe5c3fe537dd593a55464c887a92cba37ba"
)
_VERIFICATION_AMENDMENT_CORRECTION_PATH = "protocol/amendments/iter000_verification_002.json"
_VERIFICATION_AMENDMENT_CORRECTION_SHA256 = (
    "45d5d90c63bfda2b84bf962c9d7bf4c76db58fb241b7eb6d1b146a5535c7382c"
)
_VERIFICATION_AMENDMENT_CORRECTION_COMMIT = "10925e603f4dc24e1e3f990266c80300cc60ca3b"
_VERIFICATION_AMENDMENT_CORRECTION_COMMIT_TREE = "30d19a093c1704144f4dc1e43f5009d26313cdf8"
_VERIFICATION_AUTHORITY_PATH = "protocol/verification_authorities/iter000_verification_001.json"
_VERIFICATION_SIGNER_ANCHOR_PATH = "protocol/trust/iter000_verification_signer_anchor.json"
_VERIFICATION_SIGNING_KEY_PATH = ".local/keys/iter000-verification.ed25519"
_VERIFICATION_RECEIPT_PATH = (
    f"experiments/{_ITERATION_ID}/verification/attempt_001_correction_001.json"
)
_VERIFICATION_ANCHOR_ID = "iter000-verification-correction-001"
_VERIFICATION_LEDGER_SCOPE = f"{_ITERATION_ID}/attempt_001/correction_001"
_ORIGINAL_VERIFIER_SHA256 = "36a9b5fef440fc60fd8d70252db6454563f07ca9ed08887d18bc0255cf38d7e5"
_DATASET_LOCK_CORRECTION = {
    "canonical_pretty_sha256": "5dd5875185f5a96e90dc31548d24318f8182e92fe34378dce05a2c5840a4fe88",
    "path": "dataset_lock.json",
    "protocol_path": _DATASET_PROTOCOL_PATH,
    "raw_sha256": "884c1ff5daf60323437ad1d16efb01acb3e769ce71eade62fcde966bfe0a4367",
    "semantic_canonical_sha256": (
        "5721cff5c79c34e4933724d607a2a48ed9fa8936ee0c453e5fc76f14bc46082f"
    ),
}
_ATTEMPT_001_TLS_CONSTRAINTS: dict[str, object] = {
    "bypass_forbidden": True,
    "ca_bundle_sha256": _ATTEMPT_001_CA_BUNDLE_SHA256,
    "certificate_verification": "required",
    "hostname_verification": "required",
    "minimum_tls_version": "TLSv1.2",
    "trust_store": "certifi",
    "trust_store_version": _ATTEMPT_001_CERTIFI_VERSION,
}

_COMMON_BUNDLE_ARTIFACTS = frozenset(
    {
        "AMENDMENT_001.md",
        "amendment_001.json",
        "dataset_lock.json",
        "readiness_report.json",
        "RESULT.md",
        "LEARNING.json",
    }
)
_NORMAL_BUNDLE_ARTIFACTS = _COMMON_BUNDLE_ARTIFACTS | frozenset(
    {
        "coverage.json",
        "ingestion_receipt.json",
        "model_evidence_manifest.jsonl",
        "truth_manifest.jsonl",
    }
)
_INVALID_BUNDLE_ARTIFACTS = _COMMON_BUNDLE_ARTIFACTS | frozenset({"invalidity.json"})
_AUTHORITY_BUNDLE_ARTIFACTS = frozenset({_AUTHORITY_ARTIFACT, _AUTHORITY_CONSUMPTION_ARTIFACT})
_GATE_IDS = (
    "source-integrity",
    "parser-integrity",
    "truth-separation",
    "minimum-count",
    "ambiguity",
    "discriminating-action",
    "transfer-support",
    "evidence-usefulness",
)

Iter000Verdict = Literal["PASS", "BLOCKED_EVIDENCE", "INVALID"]
Iter000Flow = Literal["normal", "source-invalid", "ingestion-invalid"]
_LIFECYCLES: dict[Iter000Flow, tuple[str, ...]] = {
    "normal": (
        "run-started",
        "sources-verified",
        "dataset-ingested",
        "readiness-adjudicated",
        "run-completed",
    ),
    "source-invalid": (
        "run-started",
        "source-invalid",
        "readiness-adjudicated",
        "run-completed",
    ),
    "ingestion-invalid": (
        "run-started",
        "sources-verified",
        "ingestion-invalid",
        "readiness-adjudicated",
        "run-completed",
    ),
}
_ModelT = TypeVar("_ModelT", bound=BaseModel)


class ProofBundleVerificationError(ValueError):
    """The iter000 proof bundle is incomplete, inconsistent, or untrusted."""


class Iter000ProofVerification(BaseModel):
    """Machine-readable success receipt returned only after every check passes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["fieldtrue.iter000-proof-verification.v1"] = (
        "fieldtrue.iter000-proof-verification.v1"
    )
    run_id: Identifier
    flow: Iter000Flow
    verdict: Iter000Verdict
    signer_anchor_id: Identifier
    manifest_content_hash: Sha256
    run_manifest_hash: Sha256
    artifact_bundle_content_hash: Sha256
    artifact_bundle_hash: Sha256
    artifact_hashes: dict[str, Sha256]
    result_sha256: Sha256
    result_reproducible: Literal[True] = True
    authority_specification_sha256: Sha256 | None = None
    authority_consumption_sha256: Sha256 | None = None
    ledger_checkpoint: LedgerVerification
    ledger_verification: LedgerVerification


class Iter000CorrectedProofVerification(BaseModel):
    """Signed receipt for the single authorized verification correction."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["fieldtrue.iter000-corrected-proof-verification.v1"] = (
        "fieldtrue.iter000-corrected-proof-verification.v1"
    )
    authority_id: Identifier
    amendment_sha256: Sha256
    authority_sha256: Sha256
    proof_commit: Identifier
    proof_subtree: Identifier
    correction_applied: dict[str, str]
    consumption: dict[str, Any]
    consumption_sha256: Sha256
    verification: Iter000ProofVerification
    verification_sha256: Sha256
    resource_usage: dict[str, int | bool]
    receipt_hash: Sha256
    signer_public_key: Ed25519PublicKey
    signature: HexSignature


def _fail(message: str) -> NoReturn:
    raise ProofBundleVerificationError(message)


def _read_regular_file(path: Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        _fail(f"{label} must be a regular, non-symlink file")
    try:
        return path.read_bytes()
    except OSError as error:
        raise ProofBundleVerificationError(f"could not read {label}") from error


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _json_object(data: bytes, label: str) -> dict[str, Any]:
    try:
        decoded = data.decode("utf-8")
        value = json.loads(decoded, object_pairs_hook=_unique_object)
    except ProofBundleVerificationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProofBundleVerificationError(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        _fail(f"{label} must contain one JSON object")
    return cast(dict[str, Any], value)


def _read_json_object(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    data = _read_regular_file(path, label)
    return _json_object(data, label), data


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{label} must be a JSON object")
    return cast(dict[str, Any], value)


def _exact_keys(value: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    actual = frozenset(value)
    if actual == expected:
        return
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    _fail(f"{label} keys differ: missing={missing}, unexpected={unexpected}")


def _hash(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _fail(f"{label} must be a lowercase SHA-256 digest")
    return value


def _git_object_id(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 40
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _fail(f"{label} must be a lowercase 40-character Git object ID")
    return value


def _canonical(value: Any, data: bytes, label: str) -> None:
    if canonical_json_pretty(value) != data:
        _fail(f"{label} is not canonical pretty JSON")


def _model(model: type[_ModelT], value: Any, label: str) -> _ModelT:
    try:
        return model.model_validate(value)
    except ValidationError as error:
        raise ProofBundleVerificationError(f"{label} violates its typed schema") from error


def _git_text(repo_root: Path, *arguments: str) -> str:
    git = shutil.which("git")
    if git is None:
        _fail("Git is required to verify the correction authority")
    try:
        completed = subprocess.run(  # noqa: S603 - executable and arguments are fixed internally
            [git, *arguments],
            cwd=repo_root,
            check=True,
            capture_output=True,
            env={**os.environ, "GIT_NO_REPLACE_OBJECTS": "1"},
            text=True,
        )
    except subprocess.CalledProcessError as error:
        raise ProofBundleVerificationError(
            f"Git correction-authority check failed: {' '.join(arguments)}"
        ) from error
    return completed.stdout.strip()


def _git_blob(repo_root: Path, commit: str, relative: str) -> bytes:
    git = shutil.which("git")
    if git is None:
        _fail("Git is required to verify the correction authority")
    try:
        completed = subprocess.run(  # noqa: S603 - fixed Git object read
            [git, "show", f"{commit}:{relative}"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            env={**os.environ, "GIT_NO_REPLACE_OBJECTS": "1"},
        )
    except subprocess.CalledProcessError as error:
        raise ProofBundleVerificationError(
            f"committed correction input is unavailable: {relative}"
        ) from error
    return completed.stdout


def _selected_repo_path(repo_root: Path, requested: Path, relative: str, label: str) -> Path:
    expected = repo_root / relative
    if requested.resolve() != expected.resolve():
        _fail(f"{label} must be selected from its fixed repository path")
    return expected


def _proof_file_hashes(proof_root: Path) -> dict[str, str]:
    if proof_root.is_symlink() or not proof_root.is_dir():
        _fail("correction proof root must be a regular directory")
    try:
        entries = tuple(proof_root.iterdir())
    except OSError as error:
        raise ProofBundleVerificationError("correction proof root is unreadable") from error
    hashes: dict[str, str] = {}
    for path in entries:
        if path.is_symlink() or not path.is_file():
            _fail(f"correction proof entry must be a regular file: {path.name}")
        hashes[path.name] = sha256_file(path)
    return dict(sorted(hashes.items()))


def _load_verification_amendments(
    repo_root: Path,
) -> tuple[dict[str, Any], bytes, bytes]:
    path = repo_root / _VERIFICATION_AMENDMENT_PATH
    value, data = _read_json_object(path, "verification amendment")
    _canonical(value, data, "verification amendment")
    if sha256_bytes(data) != _VERIFICATION_AMENDMENT_SHA256:
        _fail("verification amendment differs from the prospectively committed contract")
    document_path = repo_root / _VERIFICATION_AMENDMENT_DOCUMENT_PATH
    document_data = _read_regular_file(document_path, "verification amendment document")
    if (
        value.get("schema_version") != "fieldtrue.iter000-verification-amendment.v1"
        or value.get("amendment_id") != "iter000_verification_001"
        or value.get("iteration_id") != _ITERATION_ID
        or value.get("status") != "authorized"
        or value.get("amendment_document")
        != {
            "path": _VERIFICATION_AMENDMENT_DOCUMENT_PATH,
            "sha256": _VERIFICATION_AMENDMENT_DOCUMENT_SHA256,
        }
        or sha256_bytes(document_data) != _VERIFICATION_AMENDMENT_DOCUMENT_SHA256
    ):
        _fail("verification amendment identity or document binding differs")
    correction = _object(value.get("authorized_correction"), "authorized correction")
    if (
        correction.get("correction_type") != "verification_only"
        or correction.get("maximum_corrected_verifications") != 1
        or correction.get("artifact_exception") != _DATASET_LOCK_CORRECTION
    ):
        _fail("verification amendment authorizes a different correction")
    blindness = _object(value.get("outcome_blindness"), "outcome-blindness declaration")
    if any(
        blindness.get(name) is not False
        for name in (
            "adjudication_payload_inspected",
            "learning_inspected",
            "readiness_report_inspected",
            "result_inspected",
            "verdict_inspected",
        )
    ):
        _fail("verification amendment is not outcome-blind")
    if "network_access" not in value.get("forbidden_actions", []):
        _fail("verification amendment does not forbid network access")

    proof_binding = _object(value.get("proof_binding"), "verification proof binding")
    file_hashes = _object(proof_binding.get("file_sha256"), "verification proof file map")
    if (
        proof_binding.get("artifact_count") != len(file_hashes)
        or proof_binding.get("artifact_count") != 16
        or proof_binding.get("git_commit") != _ATTEMPT_001_PROOF_COMMIT
        or proof_binding.get("git_subtree") != _ATTEMPT_001_PROOF_SUBTREE
        or proof_binding.get("path") != _ATTEMPT_001_PROOF_PATH
        or proof_binding.get("content_map_sha256") != sha256_value(file_hashes)
    ):
        _fail("verification amendment proof binding is inconsistent")
    if any(
        _hash(digest, f"verification proof hash for {name}") != digest
        for name, digest in file_hashes.items()
    ):
        _fail("verification amendment proof hash is invalid")
    committed_subtree = _git_text(
        repo_root,
        "rev-parse",
        f"{_ATTEMPT_001_PROOF_COMMIT}:{_ATTEMPT_001_PROOF_PATH}",
    )
    if committed_subtree != _ATTEMPT_001_PROOF_SUBTREE:
        _fail("committed attempt 001 proof subtree differs from the amendment")
    proof_root = repo_root / _ATTEMPT_001_PROOF_PATH
    if _proof_file_hashes(proof_root) != file_hashes:
        _fail("working attempt 001 proof differs from the immutable correction binding")
    correction_path = repo_root / _VERIFICATION_AMENDMENT_CORRECTION_PATH
    correction, correction_data = _read_json_object(
        correction_path, "verification amendment correction"
    )
    _canonical(correction, correction_data, "verification amendment correction")
    correction_document = _read_regular_file(
        repo_root / _VERIFICATION_AMENDMENT_CORRECTION_DOCUMENT_PATH,
        "verification amendment correction document",
    )
    if (
        sha256_bytes(correction_data) != _VERIFICATION_AMENDMENT_CORRECTION_SHA256
        or sha256_bytes(correction_document) != _VERIFICATION_AMENDMENT_CORRECTION_DOCUMENT_SHA256
        or correction.get("schema_version")
        != "fieldtrue.iter000-verification-amendment-correction.v1"
        or correction.get("amendment_id") != "iter000_verification_002"
        or correction.get("iteration_id") != _ITERATION_ID
        or correction.get("status") != "authorized"
        or correction.get("amendment_document")
        != {
            "path": _VERIFICATION_AMENDMENT_CORRECTION_DOCUMENT_PATH,
            "sha256": _VERIFICATION_AMENDMENT_CORRECTION_DOCUMENT_SHA256,
        }
        or correction.get("prior_amendment", {}).get("path") != _VERIFICATION_AMENDMENT_PATH
        or correction.get("prior_amendment", {}).get("sha256") != _VERIFICATION_AMENDMENT_SHA256
        or correction.get("authorized_correction")
        != {
            "corrected_value": _ATTEMPT_001_EXECUTION_COMMIT,
            "field": "trigger.execution_commit.git_commit",
            "preserved_execution_tree": "e3d8a8609e483b37c755b252e4f43b57b4731480",
            "prior_value": "ab20d41e77aba35f01352ca5cc379505205d32c8",
            "scope": "clerical_git_object_identity_only",
        }
    ):
        _fail("verification amendment clerical correction differs")
    history = (
        (_ATTEMPT_000_COMMIT, None),
        (_ATTEMPT_001_EXECUTION_COMMIT, _ATTEMPT_001_EXECUTION_TREE),
        (_ATTEMPT_001_PROOF_COMMIT, _ATTEMPT_001_PROOF_COMMIT_TREE),
        (_VERIFICATION_AMENDMENT_COMMIT, _VERIFICATION_AMENDMENT_COMMIT_TREE),
        (
            _VERIFICATION_AMENDMENT_CORRECTION_COMMIT,
            _VERIFICATION_AMENDMENT_CORRECTION_COMMIT_TREE,
        ),
    )
    for commit, expected_tree in history:
        if _git_text(repo_root, "cat-file", "-t", commit) != "commit":
            _fail("verification amendment history contains a non-commit object")
        if (
            expected_tree is not None
            and _git_text(repo_root, "rev-parse", f"{commit}^{{tree}}") != expected_tree
        ):
            _fail("verification amendment history contains a changed commit tree")
    for (parent, _), (child, _) in pairwise(history):
        _git_text(repo_root, "merge-base", "--is-ancestor", parent, child)
    _git_text(
        repo_root,
        "merge-base",
        "--is-ancestor",
        _VERIFICATION_AMENDMENT_CORRECTION_COMMIT,
        "HEAD",
    )
    if (
        _git_blob(repo_root, _VERIFICATION_AMENDMENT_COMMIT, _VERIFICATION_AMENDMENT_PATH) != data
        or _git_blob(
            repo_root,
            _VERIFICATION_AMENDMENT_COMMIT,
            _VERIFICATION_AMENDMENT_DOCUMENT_PATH,
        )
        != document_data
        or _git_blob(
            repo_root,
            _VERIFICATION_AMENDMENT_CORRECTION_COMMIT,
            _VERIFICATION_AMENDMENT_CORRECTION_PATH,
        )
        != correction_data
        or _git_blob(
            repo_root,
            _VERIFICATION_AMENDMENT_CORRECTION_COMMIT,
            _VERIFICATION_AMENDMENT_CORRECTION_DOCUMENT_PATH,
        )
        != correction_document
    ):
        _fail("verification amendment files differ from their committed chronology")
    trigger = _object(value.get("trigger"), "verification amendment trigger")
    original_verifier = _object(
        trigger.get("original_verifier"),
        "verification amendment original verifier binding",
    )
    if (
        original_verifier
        != {
            "path": "src/fieldtrue/verification.py",
            "sha256": _ORIGINAL_VERIFIER_SHA256,
        }
        or sha256_bytes(
            _git_blob(
                repo_root,
                _ATTEMPT_001_EXECUTION_COMMIT,
                "src/fieldtrue/verification.py",
            )
        )
        != _ORIGINAL_VERIFIER_SHA256
    ):
        _fail("verification amendment original verifier binding differs")
    effective = deepcopy(value)
    effective["trigger"]["execution_commit"]["git_commit"] = _ATTEMPT_001_EXECUTION_COMMIT
    return effective, data, correction_data


def _verify_dataset_lock_correction(
    value: Mapping[str, Any],
    data: bytes,
    correction: Mapping[str, Any],
) -> None:
    if dict(correction) != _DATASET_LOCK_CORRECTION:
        _fail("dataset-lock canonicality correction is not the exact authorized singleton")
    if sha256_bytes(data) != correction["raw_sha256"]:
        _fail("dataset-lock correction raw hash differs from its authority")
    if sha256_bytes(canonical_json_pretty(value)) != correction["canonical_pretty_sha256"]:
        _fail("dataset-lock correction canonical representation differs from its authority")
    if sha256_bytes(canonical_json(value)) != correction["semantic_canonical_sha256"]:
        _fail("dataset-lock correction semantic digest differs from its authority")
    if canonical_json_pretty(value) == data:
        _fail("dataset-lock correction was selected for an already canonical artifact")


def _authority_hash_map(value: Any, label: str) -> dict[str, str]:
    raw = _object(value, label)
    result: dict[str, str] = {}
    for relative, digest in raw.items():
        if (
            not isinstance(relative, str)
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
        ):
            _fail(f"{label} contains an unsafe path")
        result[relative] = _hash(digest, f"{label} hash for {relative}")
    return result


def _git_file_set(repo_root: Path, commit: str, prefix: str) -> set[str]:
    output = _git_text(repo_root, "ls-tree", "-r", "--name-only", commit, "--", prefix)
    return {line for line in output.splitlines() if line}


def _verify_implementation_hashes(
    repo_root: Path,
    *,
    commit: str,
    hashes: Mapping[str, str],
    label: str,
    require_working_tree: bool = True,
) -> None:
    for relative, expected_hash in hashes.items():
        committed_data = _git_blob(repo_root, commit, relative)
        if sha256_bytes(committed_data) != expected_hash:
            _fail(f"{label} selected-commit hash differs: {relative}")
        if require_working_tree:
            data = _read_regular_file(repo_root / relative, f"{label} file {relative}")
            if sha256_bytes(data) != expected_hash:
                _fail(f"{label} working hash differs: {relative}")
            if committed_data != data:
                _fail(f"{label} file differs from the selected implementation commit: {relative}")


def _load_verification_authority(
    repo_root: Path,
    path: Path,
    *,
    amendment: Mapping[str, Any],
    strict_selection_head: bool = True,
) -> tuple[dict[str, Any], bytes, SignerAnchor, bytes]:
    selected_path = _selected_repo_path(
        repo_root,
        path,
        _VERIFICATION_AUTHORITY_PATH,
        "verification authority",
    )
    authority, authority_data = _read_json_object(selected_path, "verification authority")
    _canonical(authority, authority_data, "verification authority")
    _exact_keys(
        authority,
        frozenset(
            {
                "schema_version",
                "authority_id",
                "iteration_id",
                "authorized_command",
                "amendments",
                "proof_binding",
                "trigger",
                "correction",
                "implementation",
                "signer_anchor",
                "consumption",
                "resource_constraints",
                "trust_model",
            }
        ),
        "verification authority",
    )
    if (
        authority["schema_version"] != "fieldtrue.iter000-verification-authority.v1"
        or authority["authority_id"] != "iter000_verification_001"
        or authority["iteration_id"] != _ITERATION_ID
        or authority["authorized_command"] != list(_CORRECTED_VERIFICATION_COMMAND)
        or authority["amendments"]
        != [
            {"path": _VERIFICATION_AMENDMENT_PATH, "sha256": _VERIFICATION_AMENDMENT_SHA256},
            {
                "path": _VERIFICATION_AMENDMENT_CORRECTION_PATH,
                "sha256": _VERIFICATION_AMENDMENT_CORRECTION_SHA256,
            },
        ]
        or authority["proof_binding"] != amendment["proof_binding"]
        or authority["trigger"] != amendment["trigger"]
        or authority["correction"] != _DATASET_LOCK_CORRECTION
    ):
        _fail("verification authority identity or frozen bindings differ")
    if authority["consumption"] != {
        "consumption_timing": "before_outcome_artifact_interpretation",
        "failure_mode": "fail_closed",
        "maximum_consumptions": 1,
        "proof_deletion_restores_authority": False,
        "receipt_path": _VERIFICATION_RECEIPT_PATH,
        "receipt_presence_consumes_authority": True,
    }:
        _fail("verification authority does not enforce one fail-closed consumption")
    if authority["resource_constraints"] != {
        "cloud_jobs": 0,
        "gpu_hours": 0,
        "network_access": False,
        "paid_calls": 0,
    }:
        _fail("verification authority permits unapproved resources")
    if authority["trust_model"] != {
        "blocks": [
            "ordinary_receipt_deletion",
            "concurrent_local_replay",
            "proof_local_authority_substitution",
        ],
        "does_not_block": [
            "same_local_owner_deletes_receipt",
            "same_local_owner_rolls_back_repository",
            "same_local_owner_controls_local_git",
            "verification_key_compromise",
        ],
        "external_timestamp": False,
        "signature": "git_pinned_separate_local_ed25519",
    }:
        _fail("verification authority misstates its local trust boundary")

    anchor_spec = _object(authority["signer_anchor"], "verification signer binding")
    anchor_path = repo_root / _VERIFICATION_SIGNER_ANCHOR_PATH
    anchor_value, anchor_data = _read_json_object(anchor_path, "verification signer anchor")
    anchor = _model(SignerAnchor, anchor_value, "verification signer anchor")
    _canonical(anchor, anchor_data, "verification signer anchor")
    execution_anchor_value, execution_anchor_data = _read_json_object(
        repo_root / _ANCHOR_PROTOCOL_PATH,
        "execution signer anchor",
    )
    execution_anchor = _model(SignerAnchor, execution_anchor_value, "execution signer anchor")
    _canonical(execution_anchor, execution_anchor_data, "execution signer anchor")
    if (
        anchor.anchor_id != _VERIFICATION_ANCHOR_ID
        or anchor.ledger_scope != _VERIFICATION_LEDGER_SCOPE
        or anchor.signer_public_key == execution_anchor.signer_public_key
        or anchor_spec
        != {
            "path": _VERIFICATION_SIGNER_ANCHOR_PATH,
            "sha256": sha256_bytes(anchor_data),
            "signer_public_key": anchor.signer_public_key,
        }
    ):
        _fail("verification authority does not bind the separately selected signer")

    implementation = _object(authority["implementation"], "verification implementation")
    _exact_keys(
        implementation,
        frozenset(
            {
                "git_commit",
                "git_tree",
                "protocol_hashes",
                "pyproject_sha256",
                "source_hashes",
                "test_hashes",
                "uv_lock_sha256",
            }
        ),
        "verification implementation",
    )
    commit = _git_object_id(implementation["git_commit"], "verification implementation commit")
    tree = _git_object_id(implementation["git_tree"], "verification implementation tree")
    if _git_text(repo_root, "rev-parse", f"{commit}^{{tree}}") != tree:
        _fail("verification implementation tree differs from its selected commit")
    _git_text(repo_root, "merge-base", "--is-ancestor", commit, "HEAD")

    source_hashes = _authority_hash_map(implementation["source_hashes"], "source map")
    test_hashes = _authority_hash_map(implementation["test_hashes"], "test map")
    if set(source_hashes) != _git_file_set(repo_root, commit, "src/fieldtrue"):
        _fail("verification authority does not bind the complete implementation source tree")
    if set(test_hashes) != _git_file_set(repo_root, commit, "tests"):
        _fail("verification authority does not bind the complete test tree")
    _verify_implementation_hashes(
        repo_root,
        commit=commit,
        hashes=source_hashes,
        label="verification source",
        require_working_tree=strict_selection_head,
    )
    _verify_implementation_hashes(
        repo_root,
        commit=commit,
        hashes=test_hashes,
        label="verification test",
        require_working_tree=strict_selection_head,
    )
    for relative, field in (
        ("pyproject.toml", "pyproject_sha256"),
        (_LOCKFILE_PROTOCOL_PATH, "uv_lock_sha256"),
    ):
        expected_hash = _hash(implementation[field], f"verification {relative} hash")
        committed_data = _git_blob(repo_root, commit, relative)
        if sha256_bytes(committed_data) != expected_hash:
            _fail(f"verification implementation differs for {relative}")
        if strict_selection_head:
            data = _read_regular_file(repo_root / relative, f"verification {relative}")
            if sha256_bytes(data) != expected_hash or committed_data != data:
                _fail(f"verification implementation differs for {relative}")

    protocol_hashes = _authority_hash_map(
        implementation["protocol_hashes"], "verification protocol map"
    )
    required_protocol_hashes = {
        _VERIFICATION_AMENDMENT_DOCUMENT_PATH,
        _VERIFICATION_AMENDMENT_PATH,
        _VERIFICATION_AMENDMENT_CORRECTION_DOCUMENT_PATH,
        _VERIFICATION_AMENDMENT_CORRECTION_PATH,
        _AUTHORITY_PROTOCOL_PATH,
        _AUTHORITY_RECEIPT_PATH,
        _ANCHOR_PROTOCOL_PATH,
        _DATASET_PROTOCOL_PATH,
        _HYPOTHESIS_PATH,
    }
    if set(protocol_hashes) != required_protocol_hashes:
        _fail("verification authority does not bind the exact correction protocol surface")
    _verify_implementation_hashes(
        repo_root,
        commit=commit,
        hashes=protocol_hashes,
        label="verification protocol",
    )

    head = _git_text(repo_root, "rev-parse", "HEAD")
    if _git_blob(repo_root, head, _VERIFICATION_AUTHORITY_PATH) != authority_data:
        _fail("verification authority is not committed at HEAD")
    if _git_blob(repo_root, head, _VERIFICATION_SIGNER_ANCHOR_PATH) != anchor_data:
        _fail("verification signer anchor is not committed at HEAD")
    changed = {
        line
        for line in _git_text(repo_root, "diff", "--name-only", f"{commit}..HEAD").splitlines()
        if line
    }
    expected_selection_changes = {
        _VERIFICATION_AUTHORITY_PATH,
        _VERIFICATION_SIGNER_ANCHOR_PATH,
    }
    if strict_selection_head and changed != expected_selection_changes:
        _fail("tracked files changed after correction implementation selection")
    if (
        _proof_file_hashes(repo_root / _ATTEMPT_001_PROOF_PATH)
        != amendment["proof_binding"]["file_sha256"]
    ):
        _fail("verification authority proof binding no longer matches the working proof")
    return authority, authority_data, anchor, anchor_data


def _parse_events(data: bytes) -> list[LedgerEvent]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProofBundleVerificationError("execution ledger is not UTF-8") from error
    events: list[LedgerEvent] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line:
            _fail(f"execution ledger contains a blank line at {line_number}")
        value = _json_object(line.encode(), f"execution ledger line {line_number}")
        events.append(_model(LedgerEvent, value, f"execution ledger line {line_number}"))
    expected = b"".join(canonical_json(event) + b"\n" for event in events)
    if data != expected:
        _fail("execution ledger is not canonical JSONL")
    return events


def _flow(events: list[LedgerEvent]) -> Iter000Flow:
    lifecycle = tuple(event.event_type for event in events)
    for flow, expected in _LIFECYCLES.items():
        if lifecycle == expected:
            return flow
    _fail("proof bundle does not have a complete allowed iter000 lifecycle")


def _payload(event: LedgerEvent, expected: frozenset[str]) -> dict[str, Any]:
    _exact_keys(event.payload, expected, f"{event.event_type} payload")
    return event.payload


def _expected_verdict(report: ReadinessReport) -> Iter000Verdict:
    if any(gate.status == GateStatus.INVALID for gate in report.gates):
        return "INVALID"
    if all(gate.status == GateStatus.PASS for gate in report.gates):
        return "PASS"
    return "BLOCKED_EVIDENCE"


def _verify_started(
    event: LedgerEvent,
    anchor_data: bytes,
    *,
    authority_required: bool = False,
) -> tuple[dict[str, Any], str | None]:
    expected_payload = {
        "hypothesis",
        "protocol_bundle",
        "gpu_authorized",
        "cloud_authorized",
        "live_action_authorized",
    }
    if authority_required:
        expected_payload.add("attempt_authority_consumption_receipt_hash")
    started = _payload(
        event,
        frozenset(expected_payload),
    )
    if started["hypothesis"] != _HYPOTHESIS_PATH:
        _fail("signed run does not identify the frozen iter000 hypothesis")
    if any(
        started[name] is not False
        for name in ("gpu_authorized", "cloud_authorized", "live_action_authorized")
    ):
        _fail("frozen iter000 forbids GPU, cloud, and live-action authorization")
    bundle = _object(started["protocol_bundle"], "signed protocol bundle")
    _exact_keys(
        bundle,
        frozenset({"schema_version", "files", "bundle_sha256"}),
        "signed protocol bundle",
    )
    if bundle["schema_version"] != "fieldtrue.protocol-bundle.v1":
        _fail("unsupported signed protocol bundle schema")
    files = _object(bundle["files"], "signed protocol files")
    for protocol_path, digest in files.items():
        _hash(digest, f"signed protocol hash for {protocol_path}")
    bundle_hash = _hash(bundle["bundle_sha256"], "signed protocol bundle hash")
    if sha256_value(files) != bundle_hash:
        _fail("signed protocol bundle content hash mismatch")
    if _HYPOTHESIS_PATH not in files:
        _fail("signed protocol bundle omits the frozen hypothesis")
    if _AMENDMENT_DOCUMENT_PATH not in files or _AMENDMENT_CONTRACT_PATH not in files:
        _fail("signed protocol bundle omits Amendment 001")
    if files.get(_ANCHOR_PROTOCOL_PATH) != sha256_bytes(anchor_data):
        _fail("signed protocol bundle does not commit to the selected signer anchor")
    if _DATASET_PROTOCOL_PATH not in files:
        _fail("signed protocol bundle omits the frozen dataset lock")
    authority_receipt_hash: str | None = None
    if authority_required:
        authority_receipt_hash = _hash(
            started["attempt_authority_consumption_receipt_hash"],
            "signed attempt-authority consumption hash",
        )
        if _AUTHORITY_PROTOCOL_PATH not in files:
            _fail("signed protocol bundle omits the trusted attempt authority")
    return files, authority_receipt_hash


def _verify_sources(event: LedgerEvent, protocol_files: Mapping[str, Any]) -> dict[str, Any]:
    sources = _payload(
        event,
        frozenset(
            {
                "dataset_id",
                "dataset_lock_hash",
                "resources",
                "network_source_only",
                "cost_usd",
            }
        ),
    )
    dataset_lock_hash = _hash(sources["dataset_lock_hash"], "signed dataset-lock hash")
    if dataset_lock_hash != protocol_files[_DATASET_PROTOCOL_PATH]:
        _fail("source event does not commit to the frozen dataset lock")
    if sources["network_source_only"] is not True or sources["cost_usd"] != "0":
        _fail("signed source receipt violates the frozen no-cost source protocol")
    if not isinstance(sources["resources"], list):
        _fail("signed source resources must be a list")
    return sources


def _verify_amendment_contract(
    proof_root: Path,
    *,
    actual_hashes: Mapping[str, str],
    protocol_files: Mapping[str, Any],
) -> None:
    amendment, amendment_data = _read_json_object(
        proof_root / "amendment_001.json", "Amendment 001 contract"
    )
    _canonical(amendment, amendment_data, "Amendment 001 contract")
    expected = {
        "schema_version": "fieldtrue.iter000-amendment.v1",
        "amendment_id": "iter000_001",
        "iteration_id": _ITERATION_ID,
        "status": "authorized",
        "amendment_document": {
            "path": _AMENDMENT_DOCUMENT_PATH,
            "sha256": actual_hashes["AMENDMENT_001.md"],
        },
        "frozen_inputs": {
            "dataset_lock": {
                "path": _DATASET_PROTOCOL_PATH,
                "sha256": protocol_files[_DATASET_PROTOCOL_PATH],
            },
            "hypothesis": {
                "path": _HYPOTHESIS_PATH,
                "sha256": protocol_files[_HYPOTHESIS_PATH],
            },
        },
        "retry_authorization": {
            "authorized_changes": {
                "administrative_controls": [
                    "attempt_output_isolation",
                    "amendment_artifact_binding",
                    "cli_attempt_routing",
                    "verifier_attempt_routing",
                    "signed_single_use_authority_consumption",
                    "gate_control_seal_regeneration",
                ],
                "infrastructure": "python_tls_trust_store",
                "scientific": "none",
            },
            "attempt_id": "attempt_001",
            "forbidden_changes": [
                "dataset",
                "hypothesis",
                "selection_rules",
                "gate_thresholds",
                "scientific_claims",
            ],
            "maximum_additional_attempts": 1,
            "tls": _ATTEMPT_001_TLS_CONSTRAINTS,
        },
        "trigger_attempt": {
            "attempt_id": "attempt_000",
            "expected_event_types": ["run-started", "run-failed"],
            "expected_head_hash": _ATTEMPT_000_HEAD_HASH,
            "expected_run_id": "iter000-2fb078a1cac5",
            "triggering_git_commit": _ATTEMPT_000_COMMIT,
            "failure": {
                "error_type": "URLError",
                "message": _ATTEMPT_000_FAILURE,
            },
            "scientific_effect": {
                "accepted_data": False,
                "result_artifact": False,
                "scientific_verdict": False,
            },
            "artifacts": {
                "ledger": {
                    "path": _ATTEMPT_000_LEDGER_PATH,
                    "sha256": _ATTEMPT_000_LEDGER_HASH,
                },
                "ledger_head": {
                    "path": _ATTEMPT_000_HEAD_PATH,
                    "sha256": _ATTEMPT_000_HEAD_FILE_HASH,
                },
                "signer_anchor": {
                    "path": _ANCHOR_PROTOCOL_PATH,
                    "sha256": protocol_files[_ANCHOR_PROTOCOL_PATH],
                },
            },
        },
    }
    if amendment != expected:
        _fail("Amendment 001 contract differs from the authorized retry contract")


def _trusted_attempt_authority(
    path: Path,
    *,
    anchor: SignerAnchor,
    anchor_data: bytes,
) -> tuple[dict[str, Any], bytes, dict[str, str]]:
    authority, authority_data = _read_json_object(path, "trusted attempt authority")
    _canonical(authority, authority_data, "trusted attempt authority")
    _exact_keys(
        authority,
        frozenset(
            {
                "schema_version",
                "authority_id",
                "iteration_id",
                "attempt_id",
                "authorized_command",
                "amendment",
                "signer_anchor",
                "protocol_hashes",
                "runtime_constraints",
                "consumption",
                "trust_model",
            }
        ),
        "trusted attempt authority",
    )
    if (
        authority["schema_version"] != "fieldtrue.attempt-authority.v1"
        or authority["authority_id"] != "iter000_001"
        or authority["iteration_id"] != _ITERATION_ID
        or authority["attempt_id"] != "attempt_001"
        or authority["authorized_command"] != list(_AUTHORIZED_COMMAND)
    ):
        _fail("trusted attempt authority has the wrong identity or command")
    if authority["amendment"] != {
        "path": _AMENDMENT_CONTRACT_PATH,
        "binding": "sha256_at_consumption",
    }:
        _fail("trusted attempt authority has the wrong amendment binding")
    if authority["signer_anchor"] != {
        "path": _ANCHOR_PROTOCOL_PATH,
        "binding": "sha256_at_consumption",
        "signer_public_key": anchor.signer_public_key,
    }:
        _fail("trusted attempt authority does not bind the selected signer")
    if authority["consumption"] != {
        "receipt_path": _AUTHORITY_RECEIPT_PATH,
        "creation_timing": "before_attempt_output_creation",
        "maximum_consumptions": 1,
        "receipt_presence_consumes_authority": True,
        "proof_deletion_restores_authority": False,
        "failure_mode": "fail_closed",
    }:
        _fail("trusted attempt authority does not enforce one fail-closed consumption")
    if authority["runtime_constraints"] != {"tls": _ATTEMPT_001_TLS_CONSTRAINTS}:
        _fail("trusted attempt authority has the wrong TLS runtime constraints")
    if authority["trust_model"] != {
        "signature": "git_pinned_local_ed25519",
        "external_timestamp": False,
        "blocks": ["ordinary_attempt_output_deletion", "concurrent_local_replay"],
        "does_not_block": [
            "same_local_owner_deletes_receipt",
            "same_local_owner_rolls_back_repository",
            "signing_key_compromise",
        ],
    }:
        _fail("trusted attempt authority misstates its local trust boundary")
    raw_protocol_hashes = _object(authority["protocol_hashes"], "authority protocol hashes")
    protocol_hashes = {
        relative: _hash(digest, f"authority protocol hash for {relative}")
        for relative, digest in raw_protocol_hashes.items()
    }
    mandatory_paths = {
        "PREREGISTRATION.md",
        "claims/registry.jsonl",
        _AMENDMENT_DOCUMENT_PATH,
        _HYPOTHESIS_PATH,
        "mission/contract.json",
        "mission/loop.json",
        "mission/name.json",
        _AMENDMENT_CONTRACT_PATH,
        "protocol/baselines/v1.json",
        _DATASET_PROTOCOL_PATH,
        "protocol/gate_controls/v1.json",
        _ANCHOR_PROTOCOL_PATH,
        "pyproject.toml",
        "src/fieldtrue/__init__.py",
        "src/fieldtrue/adapters/__init__.py",
        "src/fieldtrue/adapters/adapt.py",
        "src/fieldtrue/adapters/local_replay.py",
        "src/fieldtrue/approvals.py",
        "src/fieldtrue/canonical.py",
        "src/fieldtrue/cli.py",
        "src/fieldtrue/diagnosis.py",
        "src/fieldtrue/domain.py",
        "src/fieldtrue/experiment.py",
        "src/fieldtrue/memory.py",
        "src/fieldtrue/mission.py",
        "src/fieldtrue/planning.py",
        "src/fieldtrue/ports.py",
        "src/fieldtrue/py.typed",
        "src/fieldtrue/readiness.py",
        "src/fieldtrue/receipts.py",
        "src/fieldtrue/runtime.py",
        "src/fieldtrue/schemas.py",
        "src/fieldtrue/splits.py",
        "src/fieldtrue/verification.py",
        _LOCKFILE_PROTOCOL_PATH,
    }
    if not mandatory_paths.issubset(protocol_hashes):
        _fail("trusted attempt authority omits a mandatory protocol file")
    if protocol_hashes[_ANCHOR_PROTOCOL_PATH] != sha256_bytes(anchor_data):
        _fail("trusted attempt authority signer-anchor hash differs from the selected anchor")
    return authority, authority_data, protocol_hashes


def _verify_authorized_runtime(
    *,
    run_id: str,
    runtime: RuntimeIdentity,
    authority: Mapping[str, Any],
    protocol_hashes: Mapping[str, str],
) -> None:
    expected_run_id = f"iter000-attempt_001-{runtime.git_commit[:12]}"
    if run_id != expected_run_id:
        _fail("amended proof run_id is not the authorized attempt_001 identity")
    if (
        runtime.command != tuple(authority["authorized_command"])
        or runtime.command != _AUTHORIZED_COMMAND
        or runtime.repository_dirty is not False
        or runtime.dirty_state_hash != _CLEAN_STATE_HASH
        or runtime.lockfile_hash != protocol_hashes[_LOCKFILE_PROTOCOL_PATH]
    ):
        _fail("amended proof runtime differs from the clean authorized execution")


def _verify_authority_consumption(
    proof_root: Path,
    *,
    authority: Mapping[str, Any],
    authority_data: bytes,
    protocol_hashes: Mapping[str, str],
    anchor: SignerAnchor,
    anchor_data: bytes,
    run_id: str,
    runtime: RuntimeIdentity,
    signed_receipt_hash: str,
) -> str:
    receipt, receipt_data = _read_json_object(
        proof_root / _AUTHORITY_CONSUMPTION_ARTIFACT,
        "attempt-authority consumption receipt",
    )
    _canonical(receipt, receipt_data, "attempt-authority consumption receipt")
    _exact_keys(
        receipt,
        frozenset(
            {
                "schema_version",
                "authority_id",
                "iteration_id",
                "attempt_id",
                "run_id",
                "consumed_at",
                "authority_specification",
                "amendment",
                "signer_anchor",
                "runtime",
                "tls_runtime",
                "signer_public_key",
                "trust_level",
                "same_local_owner_can_delete_or_rollback_local_state",
                "receipt_hash",
                "signature",
            }
        ),
        "attempt-authority consumption receipt",
    )
    body = dict(receipt)
    receipt_hash = _hash(body.pop("receipt_hash"), "attempt-authority receipt hash")
    signature = body.pop("signature")
    if not isinstance(signature, str):
        _fail("attempt-authority receipt signature must be hexadecimal")
    if sha256_value(body) != receipt_hash or receipt_hash != signed_receipt_hash:
        _fail("attempt-authority consumption receipt hash mismatch")
    try:
        VerifyKey(bytes.fromhex(anchor.signer_public_key)).verify(
            bytes.fromhex(receipt_hash), bytes.fromhex(signature)
        )
    except (BadSignatureError, ValueError) as error:
        raise ProofBundleVerificationError(
            "attempt-authority consumption signature is invalid"
        ) from error
    consumed_at = receipt["consumed_at"]
    if not isinstance(consumed_at, str):
        _fail("attempt-authority consumption time must be an RFC 3339 string")
    try:
        parsed_time = datetime.fromisoformat(consumed_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise ProofBundleVerificationError(
            "attempt-authority consumption time is invalid"
        ) from error
    if parsed_time.tzinfo is None or parsed_time.utcoffset() is None:
        _fail("attempt-authority consumption time must be timezone-aware")
    if (
        receipt["schema_version"] != "fieldtrue.attempt-authority-consumption.v1"
        or receipt["authority_id"] != "iter000_001"
        or receipt["iteration_id"] != _ITERATION_ID
        or receipt["attempt_id"] != "attempt_001"
        or receipt["run_id"] != run_id
        or receipt["signer_public_key"] != anchor.signer_public_key
        or receipt["trust_level"] != "local_ed25519_no_external_timestamp"
        or receipt["same_local_owner_can_delete_or_rollback_local_state"] is not True
    ):
        _fail("attempt-authority consumption identity is inconsistent")
    if receipt["authority_specification"] != {
        "path": _AUTHORITY_PROTOCOL_PATH,
        "sha256": sha256_bytes(authority_data),
    }:
        _fail("attempt-authority consumption does not bind the trusted authority")
    if receipt["amendment"] != {
        "amendment_id": "iter000_001",
        "path": _AMENDMENT_CONTRACT_PATH,
        "sha256": protocol_hashes[_AMENDMENT_CONTRACT_PATH],
    }:
        _fail("attempt-authority consumption does not bind Amendment 001")
    if receipt["signer_anchor"] != {
        "path": _ANCHOR_PROTOCOL_PATH,
        "sha256": sha256_bytes(anchor_data),
    }:
        _fail("attempt-authority consumption does not bind the selected signer anchor")
    if receipt["tls_runtime"] != authority["runtime_constraints"]["tls"]:
        _fail("attempt-authority consumption TLS runtime differs from the selected authority")
    receipt_runtime = _model(RuntimeIdentity, receipt["runtime"], "authority receipt runtime")
    if receipt_runtime != runtime:
        _fail("attempt-authority consumption runtime differs from the signed run")
    return sha256_bytes(receipt_data)


def _verify_invalidity(
    *,
    proof_root: Path,
    flow: Literal["source-invalid", "ingestion-invalid"],
    events: Mapping[str, LedgerEvent],
    actual_hashes: Mapping[str, str],
    report: ReadinessReport,
    protocol_files: Mapping[str, Any],
    sources: Mapping[str, Any] | None,
) -> None:
    value, data = _read_json_object(proof_root / "invalidity.json", "invalidity record")
    _exact_keys(
        value,
        frozenset(
            {
                "schema_version",
                "dataset_id",
                "dataset_lock_hash",
                "stage",
                "verdict",
                "error_type",
                "message",
            }
        ),
        "invalidity record",
    )
    _canonical(value, data, "invalidity record")
    expected_stage = "source-integrity" if flow == "source-invalid" else "parser-integrity"
    if (
        value["schema_version"] != "fieldtrue.iter000-invalidity.v1"
        or value["verdict"] != "INVALID"
        or value["stage"] != expected_stage
        or value["dataset_id"] != report.dataset_id
    ):
        _fail("invalidity record is inconsistent with the INVALID readiness result")
    dataset_lock_hash = _hash(value["dataset_lock_hash"], "invalidity dataset-lock hash")
    if dataset_lock_hash != protocol_files[_DATASET_PROTOCOL_PATH]:
        _fail("invalidity record does not commit to the frozen dataset lock")
    if not isinstance(value["error_type"], str) or not value["error_type"]:
        _fail("invalidity error_type must be a non-empty string")
    if not isinstance(value["message"], str):
        _fail("invalidity message must be a string")
    event = _payload(events[flow], frozenset({"invalidity_hash", "error_type"}))
    if event != {
        "invalidity_hash": actual_hashes["invalidity.json"],
        "error_type": value["error_type"],
    }:
        _fail("signed invalidity event differs from proof/invalidity.json")
    if sources is not None and (
        sources["dataset_id"] != value["dataset_id"]
        or sources["dataset_lock_hash"] != dataset_lock_hash
    ):
        _fail("source receipt and invalidity record identify different inputs")

    expected_statuses = {
        gate_id: (
            GateStatus.INVALID
            if gate_id == expected_stage
            else GateStatus.PASS
            if flow == "ingestion-invalid" and gate_id == "source-integrity"
            else GateStatus.NOT_RUN
        )
        for gate_id in _GATE_IDS
    }
    actual_statuses = {gate.gate_id: gate.status for gate in report.gates}
    if actual_statuses != expected_statuses:
        _fail("INVALID gate states do not follow the preregistered early-stop rule")
    failed_gate = next(gate for gate in report.gates if gate.gate_id == expected_stage)
    if failed_gate.observed != {
        "error_type": value["error_type"],
        "message": value["message"],
    }:
        _fail("INVALID gate observation differs from proof/invalidity.json")


def render_iter000_result_from_proof(proof_root: Path) -> str:
    """Recreate RESULT.md using only the typed report stored in ``proof_root``."""

    if proof_root.is_symlink() or not proof_root.is_dir():
        _fail("proof root must be a regular directory")
    value, data = _read_json_object(proof_root / "readiness_report.json", "readiness report")
    report = _model(ReadinessReport, value, "readiness report")
    _canonical(report, data, "readiness report")
    return render_readiness_result(report)


def verify_iter000_proof_bundle(
    proof_root: Path,
    *,
    signer_anchor_path: Path,
    authority_specification_path: Path | None = None,
) -> Iter000ProofVerification:
    """Run the original strict verifier without any canonicality exception."""

    return _verify_iter000_proof_bundle(
        proof_root,
        signer_anchor_path=signer_anchor_path,
        authority_specification_path=authority_specification_path,
        dataset_lock_correction=None,
    )


def _verify_iter000_proof_bundle(
    proof_root: Path,
    *,
    signer_anchor_path: Path,
    authority_specification_path: Path | None = None,
    dataset_lock_correction: Mapping[str, Any] | None,
) -> Iter000ProofVerification:
    """Fail closed unless the complete iter000 result follows from pinned evidence.

    Every result artifact is read from ``proof_root``. Trust inputs are the explicitly selected,
    Git-pinned signer anchor and, for an amended run, its separately selected attempt authority.
    No raw or derived dataset path is read.
    """

    if proof_root.is_symlink() or not proof_root.is_dir():
        _fail("proof root must be a regular directory")

    anchor_value, anchor_data = _read_json_object(signer_anchor_path, "signer anchor")
    anchor = _model(SignerAnchor, anchor_value, "signer anchor")
    _canonical(anchor, anchor_data, "signer anchor")
    if anchor.anchor_id != _ANCHOR_ID or anchor.ledger_scope != _ITERATION_ID:
        _fail("signer anchor does not authorize the frozen iter000 ledger scope")

    authority: dict[str, Any] | None = None
    authority_data: bytes | None = None
    authority_protocol_hashes: dict[str, str] | None = None
    if authority_specification_path is not None:
        authority, authority_data, authority_protocol_hashes = _trusted_attempt_authority(
            authority_specification_path,
            anchor=anchor,
            anchor_data=anchor_data,
        )
    authority_required = authority is not None

    ledger_path = proof_root / "execution_ledger.jsonl"
    head_path = proof_root / "execution_ledger.head.json"
    ledger_data = _read_regular_file(ledger_path, "execution ledger")
    head_data = _read_regular_file(head_path, "execution ledger head")
    try:
        ledger_verification = verify_ledger(
            ledger_path,
            head_path,
            expected_signer_public_key=anchor.signer_public_key,
        )
    except (LedgerVerificationError, ValidationError, OSError) as error:
        raise ProofBundleVerificationError("pinned ledger verification failed") from error
    events = _parse_events(ledger_data)
    flow = _flow(events)
    events_by_type = {event.event_type: event for event in events}

    manifest, manifest_data = _read_json_object(proof_root / "run_manifest.json", "run manifest")
    _exact_keys(
        manifest,
        frozenset(
            {
                "schema_version",
                "run_id",
                "runtime",
                "artifacts",
                "ledger_checkpoint",
                "verdict",
                "manifest_content_hash",
            }
        ),
        "run manifest",
    )
    if manifest["schema_version"] != "fieldtrue.run-manifest.v1":
        _fail("unsupported run manifest schema")
    _canonical(manifest, manifest_data, "run manifest")
    manifest_body = dict(manifest)
    manifest_content_hash = _hash(
        manifest_body.pop("manifest_content_hash"), "manifest content hash"
    )
    if sha256_value(manifest_body) != manifest_content_hash:
        _fail("run manifest content hash mismatch")
    run_manifest_hash = sha256_bytes(manifest_data)

    completed = _payload(
        events_by_type["run-completed"],
        frozenset(
            {
                "verdict",
                "authorized_next_action",
                "gpu_hours",
                "cloud_jobs",
                "paid_calls",
                "artifact_bundle_hash",
                "run_manifest_hash",
            }
        ),
    )
    if _hash(completed["run_manifest_hash"], "signed run-manifest hash") != run_manifest_hash:
        _fail("signed terminal event does not commit to proof/run_manifest.json")
    if any(completed[name] != 0 for name in ("gpu_hours", "cloud_jobs", "paid_calls")):
        _fail("frozen iter000 terminal receipt must report zero accelerator and paid execution")

    run_id = manifest["run_id"]
    if not isinstance(run_id, str):
        _fail("run manifest run_id must be a string")
    runtime = _model(RuntimeIdentity, manifest["runtime"], "run manifest runtime")
    if any(event.run_id != run_id or event.runtime != runtime for event in events):
        _fail("run identity or runtime differs between manifest and signed ledger")
    if authority_required:
        assert authority is not None
        assert authority_protocol_hashes is not None
        _verify_authorized_runtime(
            run_id=run_id,
            runtime=runtime,
            authority=authority,
            protocol_hashes=authority_protocol_hashes,
        )
    elif run_id.startswith("iter000-attempt_001-"):
        _fail("attempt_001 proof verification requires a trusted authority specification")

    checkpoint = _model(
        LedgerVerification, manifest["ledger_checkpoint"], "manifest ledger checkpoint"
    )
    expected_checkpoint = LedgerVerification(
        event_count=len(events) - 1,
        head_hash=events[-2].event_hash,
        signer_public_key=anchor.signer_public_key,
        trust_level="git_pinned_ed25519_no_external_timestamp",
    )
    if checkpoint != expected_checkpoint:
        _fail("run manifest checkpoint does not match the signed preterminal ledger")

    bundle_names = _NORMAL_BUNDLE_ARTIFACTS if flow == "normal" else _INVALID_BUNDLE_ARTIFACTS
    if authority_required:
        bundle_names = bundle_names | _AUTHORITY_BUNDLE_ARTIFACTS
    manifest_names = bundle_names | frozenset({"artifact_bundle.json"})
    claimed_artifacts = _object(manifest["artifacts"], "run manifest artifacts")
    _exact_keys(claimed_artifacts, manifest_names, "run manifest artifacts")
    expected_hashes = {
        name: _hash(value, f"run manifest hash for {name}")
        for name, value in claimed_artifacts.items()
    }
    artifact_paths = {name: proof_root / name for name in sorted(manifest_names)}
    actual_hashes: dict[str, str] = {}
    for name, artifact_path in artifact_paths.items():
        _read_regular_file(artifact_path, name)
        actual_hashes[name] = sha256_file(artifact_path)
        if actual_hashes[name] != expected_hashes[name]:
            _fail(f"artifact hash mismatch for {name}")

    bundle, bundle_data = _read_json_object(proof_root / "artifact_bundle.json", "artifact bundle")
    _exact_keys(
        bundle,
        frozenset({"schema_version", "run_id", "artifacts", "bundle_sha256"}),
        "artifact bundle",
    )
    if bundle["schema_version"] != "fieldtrue.artifact-bundle.v1":
        _fail("unsupported artifact bundle schema")
    _canonical(bundle, bundle_data, "artifact bundle")
    bundle_body = dict(bundle)
    bundle_content_hash = _hash(bundle_body.pop("bundle_sha256"), "artifact bundle content hash")
    if sha256_value(bundle_body) != bundle_content_hash:
        _fail("artifact bundle content hash mismatch")
    if bundle["run_id"] != run_id:
        _fail("artifact bundle run_id differs from the signed run")
    bundled_artifacts = _object(bundle["artifacts"], "artifact bundle artifacts")
    _exact_keys(bundled_artifacts, bundle_names, "artifact bundle artifacts")
    for name, value in bundled_artifacts.items():
        digest = _hash(value, f"artifact bundle hash for {name}")
        if digest != actual_hashes[name] or digest != expected_hashes[name]:
            _fail(f"artifact bundle hash mismatch for {name}")
    if (
        _hash(completed["artifact_bundle_hash"], "signed artifact-bundle hash")
        != actual_hashes["artifact_bundle.json"]
    ):
        _fail("signed terminal event does not commit to proof/artifact_bundle.json")

    report_value, report_data = _read_json_object(
        proof_root / "readiness_report.json", "readiness report"
    )
    report = _model(ReadinessReport, report_value, "readiness report")
    _canonical(report, report_data, "readiness report")
    if report.schema_version != "fieldtrue.corpus-readiness.v1":
        _fail("unsupported readiness report schema")
    if tuple(gate.gate_id for gate in report.gates) != _GATE_IDS:
        _fail("readiness report does not contain the frozen iter000 gate sequence")
    verified_verdict = _expected_verdict(report)
    if report.verdict != verified_verdict:
        _fail("readiness verdict does not follow from the reported gate states")

    result_data = _read_regular_file(proof_root / "RESULT.md", "RESULT.md")
    rendered_result = render_readiness_result(report).encode()
    result_hash = sha256_bytes(rendered_result)
    if result_data != rendered_result or result_hash != actual_hashes["RESULT.md"]:
        _fail("RESULT.md is not reproducible from proof/readiness_report.json")

    learning, learning_data = _read_json_object(proof_root / "LEARNING.json", "iteration learning")
    _exact_keys(
        learning,
        frozenset(
            {
                "schema_version",
                "iteration_id",
                "verdict",
                "grounded_lessons",
                "engine_extraction_candidates",
                "engine_construction_authorized",
            }
        ),
        "iteration learning",
    )
    _canonical(learning, learning_data, "iteration learning")
    if (
        learning["schema_version"] != "fieldtrue.iteration-learning.v1"
        or learning["iteration_id"] != _ITERATION_ID
        or learning["verdict"] != report.verdict
        or learning["engine_construction_authorized"] is not False
    ):
        _fail("iteration learning is inconsistent with the frozen iter000 result")

    protocol_files, signed_authority_receipt_hash = _verify_started(
        events_by_type["run-started"],
        anchor_data,
        authority_required=authority_required,
    )
    authority_specification_hash: str | None = None
    authority_consumption_hash: str | None = None
    if authority_required:
        assert authority is not None
        assert authority_data is not None
        assert authority_protocol_hashes is not None
        assert signed_authority_receipt_hash is not None
        authority_specification_hash = sha256_bytes(authority_data)
        expected_protocol_files = {
            **authority_protocol_hashes,
            _AUTHORITY_PROTOCOL_PATH: authority_specification_hash,
        }
        if protocol_files != expected_protocol_files:
            _fail("signed protocol bundle differs from the trusted attempt authority")
        proof_authority_data = _read_regular_file(
            proof_root / _AUTHORITY_ARTIFACT,
            "proof-local attempt authority",
        )
        if (
            proof_authority_data != authority_data
            or actual_hashes[_AUTHORITY_ARTIFACT] != authority_specification_hash
        ):
            _fail("proof-local attempt authority differs from the selected trust input")
        authority_consumption_hash = _verify_authority_consumption(
            proof_root,
            authority=authority,
            authority_data=authority_data,
            protocol_hashes=authority_protocol_hashes,
            anchor=anchor,
            anchor_data=anchor_data,
            run_id=run_id,
            runtime=runtime,
            signed_receipt_hash=signed_authority_receipt_hash,
        )
        if authority_consumption_hash != actual_hashes[_AUTHORITY_CONSUMPTION_ARTIFACT]:
            _fail("bundled attempt-authority receipt differs from its signed content")
    dataset_lock_value, dataset_lock_data = _read_json_object(
        proof_root / "dataset_lock.json", "dataset lock"
    )
    dataset_lock = _model(AdaptDatasetLock, dataset_lock_value, "dataset lock")
    if dataset_lock_correction is None:
        _canonical(dataset_lock, dataset_lock_data, "dataset lock")
        if actual_hashes["dataset_lock.json"] != protocol_files[_DATASET_PROTOCOL_PATH]:
            _fail("proof-local dataset lock differs from the signed protocol bundle")
    else:
        if actual_hashes["dataset_lock.json"] != protocol_files[_DATASET_PROTOCOL_PATH]:
            _fail("proof-local dataset lock differs from the signed protocol bundle")
        _verify_dataset_lock_correction(
            dataset_lock_value,
            dataset_lock_data,
            dataset_lock_correction,
        )
    if actual_hashes["AMENDMENT_001.md"] != protocol_files[_AMENDMENT_DOCUMENT_PATH]:
        _fail("proof-local Amendment 001 document differs from the signed protocol bundle")
    if actual_hashes["amendment_001.json"] != protocol_files[_AMENDMENT_CONTRACT_PATH]:
        _fail("proof-local Amendment 001 contract differs from the signed protocol bundle")
    _verify_amendment_contract(
        proof_root,
        actual_hashes=actual_hashes,
        protocol_files=protocol_files,
    )
    sources: dict[str, Any] | None = None
    if flow != "source-invalid":
        sources = _verify_sources(events_by_type["sources-verified"], protocol_files)

    if flow == "normal":
        assert sources is not None
        receipt_value, receipt_data = _read_json_object(
            proof_root / "ingestion_receipt.json", "ingestion receipt"
        )
        receipt = _model(AdaptIngestionReceipt, receipt_value, "ingestion receipt")
        _canonical(receipt, receipt_data, "ingestion receipt")
        coverage_value, coverage_data = _read_json_object(
            proof_root / "coverage.json", "coverage report"
        )
        coverage = _model(AdaptCoverageReport, coverage_value, "coverage report")
        _canonical(coverage, coverage_data, "coverage report")
        if receipt.schema_version != "fieldtrue.adapt-ingestion.v1":
            _fail("unsupported ingestion receipt schema")
        if coverage.schema_version != "fieldtrue.adapt-coverage.v1":
            _fail("unsupported coverage report schema")
        if receipt.dataset_id != report.dataset_id or sources["dataset_id"] != report.dataset_id:
            _fail("dataset identity differs across source, ingestion, and readiness records")
        expected_resources = [
            resource.model_dump(mode="json") for resource in receipt.resource_receipts
        ]
        if sources["resources"] != expected_resources:
            _fail("source ledger resources differ from the ingestion receipt")
        if receipt.coverage_report_sha256 != actual_hashes["coverage.json"]:
            _fail("ingestion receipt does not commit to proof/coverage.json")
        if receipt.evidence_manifest_sha256 != actual_hashes["model_evidence_manifest.jsonl"]:
            _fail("ingestion receipt does not commit to the model evidence manifest")
        if receipt.truth_manifest_sha256 != actual_hashes["truth_manifest.jsonl"]:
            _fail("ingestion receipt does not commit to the proof-local truth manifest")
        ingested = _payload(
            events_by_type["dataset-ingested"],
            frozenset(
                {
                    "ingestion_receipt_hash",
                    "coverage_hash",
                    "model_evidence_manifest_hash",
                    "evidence_manifest_hash",
                    "truth_manifest_hash",
                    "truth_separation_passed",
                }
            ),
        )
        if ingested != {
            "ingestion_receipt_hash": actual_hashes["ingestion_receipt.json"],
            "coverage_hash": actual_hashes["coverage.json"],
            "model_evidence_manifest_hash": actual_hashes["model_evidence_manifest.jsonl"],
            "evidence_manifest_hash": receipt.evidence_manifest_sha256,
            "truth_manifest_hash": actual_hashes["truth_manifest.jsonl"],
            "truth_separation_passed": receipt.truth_separation_passed,
        }:
            _fail("signed ingestion event differs from proof-local ingestion commitments")
        try:
            recomputed_report = audit_adapt_proof_readiness(
                dataset_lock,
                receipt,
                coverage,
                proof_root / "coverage.json",
                proof_root / "model_evidence_manifest.jsonl",
                proof_root / "truth_manifest.jsonl",
            )
        except (OSError, UnicodeError, ValueError) as error:
            raise ProofBundleVerificationError(
                "proof-local readiness recomputation failed"
            ) from error
        if report != recomputed_report:
            _fail("readiness report differs from independent proof-local recomputation")
        verified_verdict = _expected_verdict(recomputed_report)
    else:
        _verify_invalidity(
            proof_root=proof_root,
            flow=flow,
            events=events_by_type,
            actual_hashes=actual_hashes,
            report=report,
            protocol_files=protocol_files,
            sources=sources,
        )

    adjudicated = _payload(
        events_by_type["readiness-adjudicated"],
        frozenset(
            {
                "verdict",
                "readiness_report_hash",
                "result_hash",
                "learning_hash",
                "gate_statuses",
            }
        ),
    )
    if adjudicated != {
        "verdict": report.verdict,
        "readiness_report_hash": actual_hashes["readiness_report.json"],
        "result_hash": result_hash,
        "learning_hash": actual_hashes["LEARNING.json"],
        "gate_statuses": {gate.gate_id: gate.status.value for gate in report.gates},
    }:
        _fail("signed readiness adjudication differs from the proof-local result")
    if (
        completed["verdict"] != report.verdict
        or completed["authorized_next_action"] != report.authorized_next_action
    ):
        _fail("signed terminal verdict differs from the proof-local readiness result")
    if manifest["verdict"] != report.verdict:
        _fail("run manifest verdict differs from the signed readiness result")

    for name, artifact_path in artifact_paths.items():
        if sha256_file(artifact_path) != actual_hashes[name]:
            _fail(f"artifact changed during verification: {name}")
    if _read_regular_file(proof_root / "run_manifest.json", "run manifest") != manifest_data:
        _fail("run manifest changed during verification")
    if _read_regular_file(signer_anchor_path, "signer anchor") != anchor_data:
        _fail("signer anchor changed during verification")
    if (
        authority_specification_path is not None
        and authority_data is not None
        and _read_regular_file(authority_specification_path, "trusted attempt authority")
        != authority_data
    ):
        _fail("trusted attempt authority changed during verification")
    if _read_regular_file(ledger_path, "execution ledger") != ledger_data:
        _fail("execution ledger changed during verification")
    if _read_regular_file(head_path, "execution ledger head") != head_data:
        _fail("execution ledger head changed during verification")

    return Iter000ProofVerification(
        run_id=run_id,
        flow=flow,
        verdict=verified_verdict,
        signer_anchor_id=anchor.anchor_id,
        manifest_content_hash=manifest_content_hash,
        run_manifest_hash=run_manifest_hash,
        artifact_bundle_content_hash=bundle_content_hash,
        artifact_bundle_hash=actual_hashes["artifact_bundle.json"],
        artifact_hashes=actual_hashes,
        result_sha256=result_hash,
        authority_specification_sha256=authority_specification_hash,
        authority_consumption_sha256=authority_consumption_hash,
        ledger_checkpoint=checkpoint,
        ledger_verification=ledger_verification,
    )


def initialize_iter000_verification_signer(repo_root: Path) -> SignerAnchor:
    """Create the correction signer separately from the scientific execution signer."""

    key = load_or_create_signing_key(repo_root / _VERIFICATION_SIGNING_KEY_PATH)
    execution_anchor = load_signer_anchor(repo_root / _ANCHOR_PROTOCOL_PATH)
    if key.verify_key.encode().hex() == execution_anchor.signer_public_key:
        _fail("verification signer must differ from the scientific execution signer")
    return write_signer_anchor(
        repo_root / _VERIFICATION_SIGNER_ANCHOR_PATH,
        key,
        anchor_id=_VERIFICATION_ANCHOR_ID,
        ledger_scope=_VERIFICATION_LEDGER_SCOPE,
    )


def _signed_record(
    body: Mapping[str, Any],
    *,
    signing_key: SigningKey,
    hash_field: str,
) -> dict[str, Any]:
    digest = sha256_value(body)
    signature = signing_key.sign(bytes.fromhex(digest)).signature.hex()
    return {**body, hash_field: digest, "signature": signature}


def _verify_signed_record(
    value: Mapping[str, Any],
    *,
    anchor: SignerAnchor,
    hash_field: str,
    label: str,
) -> str:
    body = dict(value)
    signature = body.pop("signature", None)
    digest = body.pop(hash_field, None)
    digest = _hash(digest, f"{label} hash")
    if not isinstance(signature, str) or sha256_value(body) != digest:
        _fail(f"{label} content hash differs")
    try:
        VerifyKey(bytes.fromhex(anchor.signer_public_key)).verify(
            bytes.fromhex(digest), bytes.fromhex(signature)
        )
    except (BadSignatureError, ValueError) as error:
        raise ProofBundleVerificationError(f"{label} signature is invalid") from error
    return digest


def _exclusive_receipt_write(path: Path, data: bytes) -> None:
    directory = path.parent
    if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
        _fail("verification receipt directory must not be linked")
    directory.mkdir(parents=True, exist_ok=True)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | no_follow
    directory_descriptor = os.open(directory, directory_flags)
    descriptor: int | None = None
    try:
        try:
            descriptor = os.open(
                path.name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow,
                0o444,
                dir_fd=directory_descriptor,
            )
        except FileExistsError as error:
            raise ProofBundleVerificationError(
                "verification correction authority is already consumed"
            ) from error
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                _fail("verification consumption receipt must be a regular file")
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.fsync(directory_descriptor)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory_descriptor)


def _consumption_record(
    *,
    authority: Mapping[str, Any],
    authority_data: bytes,
    amendment: Mapping[str, Any],
    runtime: RuntimeIdentity,
    signer_public_key: str,
    signing_key: SigningKey,
) -> dict[str, Any]:
    body = {
        "schema_version": "fieldtrue.iter000-verification-authority-consumption.v1",
        "authority_id": authority["authority_id"],
        "iteration_id": _ITERATION_ID,
        "attempt_id": "attempt_001",
        "correction_id": "correction_001",
        "consumed_at": datetime.now(UTC),
        "amendments": authority["amendments"],
        "authority": {
            "path": _VERIFICATION_AUTHORITY_PATH,
            "sha256": sha256_bytes(authority_data),
        },
        "proof_binding": {
            "content_map_sha256": amendment["proof_binding"]["content_map_sha256"],
            "git_commit": _ATTEMPT_001_PROOF_COMMIT,
            "git_subtree": _ATTEMPT_001_PROOF_SUBTREE,
        },
        "runtime": runtime.model_dump(mode="json"),
        "signer_public_key": signer_public_key,
        "trust_level": "git_pinned_separate_local_ed25519_no_external_timestamp",
        "same_local_owner_can_delete_or_rollback_local_state": True,
    }
    return _signed_record(body, signing_key=signing_key, hash_field="consumption_hash")


def _verify_consumption_record(
    value: Mapping[str, Any],
    *,
    authority: Mapping[str, Any],
    authority_data: bytes,
    amendment: Mapping[str, Any],
    anchor: SignerAnchor,
) -> str:
    _exact_keys(
        value,
        frozenset(
            {
                "schema_version",
                "authority_id",
                "iteration_id",
                "attempt_id",
                "correction_id",
                "consumed_at",
                "amendments",
                "authority",
                "proof_binding",
                "runtime",
                "signer_public_key",
                "trust_level",
                "same_local_owner_can_delete_or_rollback_local_state",
                "consumption_hash",
                "signature",
            }
        ),
        "verification consumption receipt",
    )
    runtime = _model(RuntimeIdentity, value["runtime"], "verification consumption runtime")
    consumed_at = value["consumed_at"]
    if not isinstance(consumed_at, str):
        _fail("verification consumption timestamp must be an RFC 3339 string")
    try:
        parsed_time = datetime.fromisoformat(consumed_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise ProofBundleVerificationError(
            "verification consumption timestamp is invalid"
        ) from error
    if (
        parsed_time.tzinfo is None
        or parsed_time.utcoffset() is None
        or value["schema_version"] != "fieldtrue.iter000-verification-authority-consumption.v1"
        or value["authority_id"] != authority["authority_id"]
        or value["iteration_id"] != _ITERATION_ID
        or value["attempt_id"] != "attempt_001"
        or value["correction_id"] != "correction_001"
        or value["amendments"] != authority["amendments"]
        or value["authority"]
        != {
            "path": _VERIFICATION_AUTHORITY_PATH,
            "sha256": sha256_bytes(authority_data),
        }
        or value["proof_binding"]
        != {
            "content_map_sha256": amendment["proof_binding"]["content_map_sha256"],
            "git_commit": _ATTEMPT_001_PROOF_COMMIT,
            "git_subtree": _ATTEMPT_001_PROOF_SUBTREE,
        }
        or runtime.command != _CORRECTED_VERIFICATION_COMMAND
        or runtime.repository_dirty is not False
        or runtime.dirty_state_hash != _CLEAN_STATE_HASH
        or value["signer_public_key"] != anchor.signer_public_key
        or value["trust_level"] != "git_pinned_separate_local_ed25519_no_external_timestamp"
        or value["same_local_owner_can_delete_or_rollback_local_state"] is not True
    ):
        _fail("verification consumption receipt differs from its authority")
    return _verify_signed_record(
        value,
        anchor=anchor,
        hash_field="consumption_hash",
        label="verification consumption receipt",
    )


def verify_iter000_proof_bundle_correction_001(
    repo_root: Path,
    *,
    command: tuple[str, ...],
) -> Iter000CorrectedProofVerification:
    """Consume and execute the sole authorized correction against the immutable proof."""

    if command != _CORRECTED_VERIFICATION_COMMAND:
        _fail("corrected verification command differs from its authority")
    amendment, amendment_001_data, amendment_002_data = _load_verification_amendments(repo_root)
    authority, authority_data, verification_anchor, verification_anchor_data = (
        _load_verification_authority(
            repo_root,
            repo_root / _VERIFICATION_AUTHORITY_PATH,
            amendment=amendment,
        )
    )
    receipt_path = repo_root / _VERIFICATION_RECEIPT_PATH
    if receipt_path.is_symlink() or receipt_path.exists():
        _fail("verification correction authority is already consumed")
    runtime = collect_runtime_identity(repo_root, command=command, require_clean=True)
    if runtime.git_commit != _git_text(
        repo_root, "rev-parse", "HEAD"
    ) or runtime.git_tree != _git_text(repo_root, "rev-parse", "HEAD^{tree}"):
        _fail("verification runtime differs from the replacement-disabled selected HEAD")
    signing_key = load_or_create_signing_key(repo_root / _VERIFICATION_SIGNING_KEY_PATH)
    if signing_key.verify_key.encode().hex() != verification_anchor.signer_public_key:
        _fail("local verification key does not match the selected signer anchor")
    consumption = _consumption_record(
        authority=authority,
        authority_data=authority_data,
        amendment=amendment,
        runtime=runtime,
        signer_public_key=verification_anchor.signer_public_key,
        signing_key=signing_key,
    )
    consumption_data = canonical_json_pretty(consumption)
    _exclusive_receipt_write(receipt_path, consumption_data)

    verification = _verify_iter000_proof_bundle(
        repo_root / _ATTEMPT_001_PROOF_PATH,
        signer_anchor_path=repo_root / _ANCHOR_PROTOCOL_PATH,
        authority_specification_path=repo_root / _AUTHORITY_PROTOCOL_PATH,
        dataset_lock_correction=_DATASET_LOCK_CORRECTION,
    )

    amendment_after, amendment_001_after, amendment_002_after = _load_verification_amendments(
        repo_root
    )
    authority_after, authority_data_after, anchor_after, anchor_data_after = (
        _load_verification_authority(
            repo_root,
            repo_root / _VERIFICATION_AUTHORITY_PATH,
            amendment=amendment_after,
        )
    )
    if (
        amendment_after != amendment
        or amendment_001_after != amendment_001_data
        or amendment_002_after != amendment_002_data
        or authority_after != authority
        or authority_data_after != authority_data
        or anchor_after != verification_anchor
        or anchor_data_after != verification_anchor_data
        or _read_regular_file(receipt_path, "verification consumption receipt") != consumption_data
        or _proof_file_hashes(repo_root / _ATTEMPT_001_PROOF_PATH)
        != amendment["proof_binding"]["file_sha256"]
    ):
        _fail("verification trust input changed during corrected verification")

    verification_value = verification.model_dump(mode="json")
    receipt_body = {
        "schema_version": "fieldtrue.iter000-corrected-proof-verification.v1",
        "authority_id": authority["authority_id"],
        "amendment_sha256": _VERIFICATION_AMENDMENT_CORRECTION_SHA256,
        "authority_sha256": sha256_bytes(authority_data),
        "proof_commit": _ATTEMPT_001_PROOF_COMMIT,
        "proof_subtree": _ATTEMPT_001_PROOF_SUBTREE,
        "correction_applied": _DATASET_LOCK_CORRECTION,
        "consumption": consumption,
        "consumption_sha256": sha256_bytes(consumption_data),
        "verification": verification_value,
        "verification_sha256": sha256_value(verification_value),
        "resource_usage": {
            "cloud_jobs": 0,
            "gpu_hours": 0,
            "network_access": False,
            "paid_calls": 0,
        },
        "signer_public_key": verification_anchor.signer_public_key,
    }
    final_value = _signed_record(
        receipt_body,
        signing_key=signing_key,
        hash_field="receipt_hash",
    )
    final_receipt = Iter000CorrectedProofVerification.model_validate(final_value)
    atomic_write(receipt_path, canonical_json_pretty(final_receipt), mode=0o444)
    return final_receipt


def _verify_final_correction_receipt(
    value: Mapping[str, Any],
    data: bytes,
    *,
    authority: Mapping[str, Any],
    authority_data: bytes,
    amendment: Mapping[str, Any],
    anchor: SignerAnchor,
) -> Iter000CorrectedProofVerification:
    receipt = _model(
        Iter000CorrectedProofVerification,
        value,
        "corrected verification receipt",
    )
    _canonical(receipt, data, "corrected verification receipt")
    consumption = _object(value["consumption"], "corrected verification consumption")
    _verify_consumption_record(
        consumption,
        authority=authority,
        authority_data=authority_data,
        amendment=amendment,
        anchor=anchor,
    )
    verification_value = _object(value["verification"], "corrected proof verification")
    if (
        receipt.authority_id != authority["authority_id"]
        or receipt.amendment_sha256 != _VERIFICATION_AMENDMENT_CORRECTION_SHA256
        or receipt.authority_sha256 != sha256_bytes(authority_data)
        or receipt.proof_commit != _ATTEMPT_001_PROOF_COMMIT
        or receipt.proof_subtree != _ATTEMPT_001_PROOF_SUBTREE
        or receipt.correction_applied != _DATASET_LOCK_CORRECTION
        or receipt.consumption_sha256 != sha256_bytes(canonical_json_pretty(consumption))
        or receipt.verification_sha256 != sha256_value(verification_value)
        or receipt.resource_usage
        != {
            "cloud_jobs": 0,
            "gpu_hours": 0,
            "network_access": False,
            "paid_calls": 0,
        }
        or receipt.signer_public_key != anchor.signer_public_key
        or receipt.verification.authority_specification_sha256
        != authority["trigger"]["execution_authority"]["sha256"]
        or receipt.verification.authority_consumption_sha256
        != authority["trigger"]["authority_consumption"]["sha256"]
    ):
        _fail("corrected verification receipt differs from its frozen authority")
    _verify_signed_record(
        value,
        anchor=anchor,
        hash_field="receipt_hash",
        label="corrected verification receipt",
    )
    return receipt


def validate_iter000_verification_correction_surface(repo_root: Path) -> tuple[bool, str]:
    """Validate correction chronology and authority without reading scientific outcomes."""

    try:
        amendment, _, _ = _load_verification_amendments(repo_root)
        authority, authority_data, anchor, _ = _load_verification_authority(
            repo_root,
            repo_root / _VERIFICATION_AUTHORITY_PATH,
            amendment=amendment,
            strict_selection_head=False,
        )
        receipt_path = repo_root / _VERIFICATION_RECEIPT_PATH
        if not receipt_path.exists():
            return (
                True,
                "Verification correction authority is committed, exact, and unconsumed.",
            )
        value, data = _read_json_object(receipt_path, "verification correction receipt")
        schema_version = value.get("schema_version")
        if schema_version == "fieldtrue.iter000-verification-authority-consumption.v1":
            _canonical(value, data, "verification consumption receipt")
            _verify_consumption_record(
                value,
                authority=authority,
                authority_data=authority_data,
                amendment=amendment,
                anchor=anchor,
            )
            return (
                False,
                "Verification correction authority was consumed without a completed receipt.",
            )
        if schema_version != "fieldtrue.iter000-corrected-proof-verification.v1":
            _fail("verification correction receipt has an unsupported schema")
        _verify_final_correction_receipt(
            value,
            data,
            authority=authority,
            authority_data=authority_data,
            amendment=amendment,
            anchor=anchor,
        )
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        return False, f"Verification correction surface is invalid: {type(error).__name__}: {error}"
    return True, "Verification correction receipt is signed, complete, and proof-bound."
