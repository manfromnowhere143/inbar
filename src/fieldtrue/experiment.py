"""Pre-registered experiment runners."""

from __future__ import annotations

import fcntl
import json
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as distribution_version
from pathlib import Path
from typing import Any

import certifi
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from fieldtrue.adapters.adapt import (
    fetch_adapt_dataset,
    ingest_adapt_dataset,
    load_adapt_lock,
)
from fieldtrue.canonical import (
    atomic_write,
    canonical_json_pretty,
    read_json,
    sha256_file,
    sha256_value,
)
from fieldtrue.domain import Ed25519PublicKey, ReadinessReport
from fieldtrue.readiness import (
    audit_adapt_readiness,
    invalid_readiness_report,
    write_readiness_artifacts,
)
from fieldtrue.receipts import (
    SignedLedger,
    load_or_create_signing_key,
    load_signer_anchor,
    verify_ledger,
)
from fieldtrue.runtime import RuntimeIdentity, collect_runtime_identity
from fieldtrue.verification import (
    ProofBundleVerificationError,
    verify_iter000_proof_bundle,
)


class ExperimentAlreadyExecutedError(RuntimeError):
    pass


class ExperimentPreflightError(RuntimeError):
    pass


class ExperimentFinalizationError(RuntimeError):
    """A terminally sealed run failed independent proof verification."""


_ATTEMPT_001_AUTHORITY_SPEC_PATH = "protocol/attempt_authorities/iter000_001.json"
_ATTEMPT_001_RECEIPT_PATH = (
    "experiments/iter000_nasa_adapt_corpus_readiness/authority/attempt_001_consumption.json"
)
_ATTEMPT_001_AMENDMENT_PATH = "protocol/amendments/iter000_001.json"
_ITER000_SIGNER_ANCHOR_PATH = "protocol/trust/iter000_signer_anchor.json"
_ATTEMPT_001_CERTIFI_VERSION = "2026.6.17"
_ATTEMPT_001_CA_BUNDLE_SHA256 = "bbc7e9c01d7551bb8a159b5dedd989b8ee3ce105aff522b68eb1b01bf854cab0"
_ATTEMPT_001_TLS_CONSTRAINTS: dict[str, object] = {
    "bypass_forbidden": True,
    "ca_bundle_sha256": _ATTEMPT_001_CA_BUNDLE_SHA256,
    "certificate_verification": "required",
    "hostname_verification": "required",
    "minimum_tls_version": "TLSv1.2",
    "trust_store": "certifi",
    "trust_store_version": _ATTEMPT_001_CERTIFI_VERSION,
}
_ATTEMPT_001_PROTOCOL_HASH_PATHS = (
    "PREREGISTRATION.md",
    "claims/registry.jsonl",
    "experiments/iter000_nasa_adapt_corpus_readiness/AMENDMENT_001.md",
    "experiments/iter000_nasa_adapt_corpus_readiness/HYPOTHESIS.md",
    "mission/contract.json",
    "mission/loop.json",
    "mission/name.json",
    "protocol/amendments/iter000_001.json",
    "protocol/baselines/v1.json",
    "protocol/datasets/nasa_adapt_v1.json",
    "protocol/gate_controls/v1.json",
    _ITER000_SIGNER_ANCHOR_PATH,
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
    "uv.lock",
)
_ATTEMPT_001_AUTHORITY_SPEC: dict[str, object] = {
    "schema_version": "fieldtrue.attempt-authority.v1",
    "authority_id": "iter000_001",
    "iteration_id": "iter000_nasa_adapt_corpus_readiness",
    "attempt_id": "attempt_001",
    "authorized_command": [
        "fieldtrue",
        "experiment",
        "iter000-amendment-001",
    ],
    "amendment": {
        "path": _ATTEMPT_001_AMENDMENT_PATH,
        "binding": "sha256_at_consumption",
    },
    "signer_anchor": {
        "path": _ITER000_SIGNER_ANCHOR_PATH,
        "binding": "sha256_at_consumption",
        "signer_public_key": None,
    },
    "protocol_hashes": None,
    "runtime_constraints": {
        "tls": _ATTEMPT_001_TLS_CONSTRAINTS,
    },
    "consumption": {
        "receipt_path": _ATTEMPT_001_RECEIPT_PATH,
        "creation_timing": "before_attempt_output_creation",
        "maximum_consumptions": 1,
        "receipt_presence_consumes_authority": True,
        "proof_deletion_restores_authority": False,
        "failure_mode": "fail_closed",
    },
    "trust_model": {
        "signature": "git_pinned_local_ed25519",
        "external_timestamp": False,
        "blocks": [
            "ordinary_attempt_output_deletion",
            "concurrent_local_replay",
        ],
        "does_not_block": [
            "same_local_owner_deletes_receipt",
            "same_local_owner_rolls_back_repository",
            "signing_key_compromise",
        ],
    },
}


@contextmanager
def _exclusive_run_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ExperimentPreflightError("iteration 000 is already running") from error
        yield
    finally:
        os.close(descriptor)


def _load_attempt_001_authority_specification(repo_root: Path) -> tuple[Path, dict[str, Any]]:
    path = repo_root / _ATTEMPT_001_AUTHORITY_SPEC_PATH
    if path.is_symlink() or not path.is_file():
        raise ExperimentPreflightError(
            "attempt 001 authority specification must be a committed regular file"
        )
    try:
        specification = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ExperimentPreflightError("attempt 001 authority specification is invalid") from error
    if not isinstance(specification, dict):
        raise ExperimentPreflightError("attempt 001 authority specification must be an object")
    protocol_hashes = specification.get("protocol_hashes")
    signer_anchor = specification.get("signer_anchor")
    if not isinstance(protocol_hashes, dict) or not isinstance(signer_anchor, dict):
        raise ExperimentPreflightError("attempt 001 authority specification bindings are invalid")
    signer_public_key = signer_anchor.get("signer_public_key")
    normalized = dict(specification)
    normalized["protocol_hashes"] = None
    normalized["signer_anchor"] = {**signer_anchor, "signer_public_key": None}
    if normalized != _ATTEMPT_001_AUTHORITY_SPEC:
        raise ExperimentPreflightError(
            "attempt 001 authority specification differs from the executable contract"
        )
    if not isinstance(signer_public_key, str) or len(signer_public_key) != 64:
        raise ExperimentPreflightError("attempt 001 authority signer key is malformed")
    schema_paths = tuple(
        candidate.relative_to(repo_root).as_posix()
        for candidate in sorted((repo_root / "protocol" / "schemas").glob("*.json"))
    )
    expected_protocol_paths = (*_ATTEMPT_001_PROTOCOL_HASH_PATHS, *schema_paths)
    if set(protocol_hashes) != set(expected_protocol_paths):
        raise ExperimentPreflightError("attempt 001 authority protocol hash surface is incomplete")
    for relative_path in expected_protocol_paths:
        expected_hash = protocol_hashes.get(relative_path)
        target = repo_root / relative_path
        if target.is_symlink() or not target.is_file():
            raise ExperimentPreflightError(
                f"attempt 001 authority protocol file is unavailable: {relative_path}"
            )
        if expected_hash != sha256_file(target):
            raise ExperimentPreflightError(
                f"attempt 001 authority protocol hash mismatch: {relative_path}"
            )
    return path, specification


def _authority_receipt_body(receipt: dict[str, Any]) -> dict[str, Any]:
    body = dict(receipt)
    body.pop("receipt_hash", None)
    body.pop("signature", None)
    return body


def _verify_attempt_authority_consumption(
    path: Path,
    *,
    expected_signer_public_key: str,
) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ExperimentPreflightError("attempt authority receipt must be a regular file")
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ExperimentPreflightError("attempt authority receipt is invalid") from error
    if not isinstance(receipt, dict):
        raise ExperimentPreflightError("attempt authority receipt must be an object")
    body = _authority_receipt_body(receipt)
    receipt_hash = receipt.get("receipt_hash")
    signature = receipt.get("signature")
    if receipt_hash != sha256_value(body):
        raise ExperimentPreflightError("attempt authority receipt hash mismatch")
    if receipt.get("signer_public_key") != expected_signer_public_key:
        raise ExperimentPreflightError("attempt authority receipt signer mismatch")
    if not isinstance(receipt_hash, str) or not isinstance(signature, str):
        raise ExperimentPreflightError("attempt authority receipt signature is missing")
    try:
        VerifyKey(bytes.fromhex(expected_signer_public_key)).verify(
            bytes.fromhex(receipt_hash), bytes.fromhex(signature)
        )
    except (BadSignatureError, ValueError) as error:
        raise ExperimentPreflightError("attempt authority receipt signature mismatch") from error
    return receipt


def _write_attempt_001_authority_consumption(
    repo_root: Path,
    *,
    run_id: str,
    runtime: RuntimeIdentity,
    signing_key: SigningKey,
    signer_public_key: str,
    authority_specification_path: Path,
    authority_specification: dict[str, Any],
) -> tuple[Path, str]:
    receipt_path = repo_root / _ATTEMPT_001_RECEIPT_PATH
    if receipt_path.is_symlink() or receipt_path.exists():
        raise ExperimentAlreadyExecutedError(
            "iteration 000 attempt 001 authority is already consumed"
        )
    receipt_directory = receipt_path.parent
    receipt_container = receipt_directory.parent
    if receipt_container.is_symlink() or not receipt_container.is_dir():
        raise ExperimentPreflightError("attempt authority container must be a regular directory")
    if receipt_directory.is_symlink() or (
        receipt_directory.exists() and not receipt_directory.is_dir()
    ):
        raise ExperimentPreflightError("attempt authority directory must not be linked")
    amendment_path = repo_root / _ATTEMPT_001_AMENDMENT_PATH
    signer_anchor_path = repo_root / _ITER000_SIGNER_ANCHOR_PATH
    for label, path in (
        ("amendment", amendment_path),
        ("signer anchor", signer_anchor_path),
    ):
        if path.is_symlink() or not path.is_file():
            raise ExperimentPreflightError(f"attempt authority {label} must be a regular file")
    certifi_path = Path(certifi.where())
    runtime_constraints = authority_specification.get("runtime_constraints")
    tls_constraints = (
        runtime_constraints.get("tls") if isinstance(runtime_constraints, dict) else None
    )
    try:
        certifi_version = distribution_version("certifi")
    except PackageNotFoundError as error:
        raise ExperimentPreflightError("attempt authority TLS runtime is unavailable") from error
    if (
        certifi_path.is_symlink()
        or not certifi_path.is_file()
        or not isinstance(tls_constraints, dict)
        or certifi_version != _ATTEMPT_001_CERTIFI_VERSION
        or sha256_file(certifi_path) != _ATTEMPT_001_CA_BUNDLE_SHA256
        or tls_constraints != _ATTEMPT_001_TLS_CONSTRAINTS
    ):
        raise ExperimentPreflightError("attempt authority TLS runtime differs from its lock")
    body: dict[str, object] = {
        "schema_version": "fieldtrue.attempt-authority-consumption.v1",
        "authority_id": "iter000_001",
        "iteration_id": "iter000_nasa_adapt_corpus_readiness",
        "attempt_id": "attempt_001",
        "run_id": run_id,
        "consumed_at": datetime.now(UTC),
        "authority_specification": {
            "path": _ATTEMPT_001_AUTHORITY_SPEC_PATH,
            "sha256": sha256_file(authority_specification_path),
        },
        "amendment": {
            "amendment_id": "iter000_001",
            "path": _ATTEMPT_001_AMENDMENT_PATH,
            "sha256": sha256_file(amendment_path),
        },
        "signer_anchor": {
            "path": _ITER000_SIGNER_ANCHOR_PATH,
            "sha256": sha256_file(signer_anchor_path),
        },
        "runtime": runtime,
        "tls_runtime": tls_constraints,
        "signer_public_key": signer_public_key,
        "trust_level": "local_ed25519_no_external_timestamp",
        "same_local_owner_can_delete_or_rollback_local_state": True,
    }
    receipt_hash = sha256_value(body)
    receipt = {
        **body,
        "receipt_hash": receipt_hash,
        "signature": signing_key.sign(bytes.fromhex(receipt_hash)).signature.hex(),
    }
    data = canonical_json_pretty(receipt)
    receipt_directory.mkdir(exist_ok=True)
    if receipt_directory.is_symlink() or not receipt_directory.is_dir():
        raise ExperimentPreflightError("attempt authority directory must be a regular directory")
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory_only = getattr(os, "O_DIRECTORY", 0)
    container_descriptor = os.open(
        receipt_container,
        os.O_RDONLY | directory_only | no_follow,
    )
    try:
        os.fsync(container_descriptor)
        directory_descriptor = os.open(
            receipt_directory,
            os.O_RDONLY | directory_only | no_follow,
        )
    finally:
        os.close(container_descriptor)
    try:
        try:
            descriptor = os.open(
                receipt_path.name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow,
                0o444,
                dir_fd=directory_descriptor,
            )
        except FileExistsError as error:
            raise ExperimentAlreadyExecutedError(
                "iteration 000 attempt 001 authority is already consumed"
            ) from error
        # Any failure after the exclusive create leaves authority consumed and fails closed.
        with os.fdopen(descriptor, "wb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise ExperimentPreflightError("attempt authority receipt must be a regular file")
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)
    verified = _verify_attempt_authority_consumption(
        receipt_path,
        expected_signer_public_key=signer_public_key,
    )
    if verified.get("receipt_hash") != receipt_hash:
        raise ExperimentPreflightError("attempt authority receipt self-verification failed")
    return receipt_path, receipt_hash


def _protocol_bundle(repo_root: Path) -> dict[str, object]:
    authority = read_json(repo_root / _ATTEMPT_001_AUTHORITY_SPEC_PATH)
    protocol_hashes = authority.get("protocol_hashes")
    if not isinstance(protocol_hashes, dict) or not all(
        isinstance(relative, str) for relative in protocol_hashes
    ):
        raise ExperimentPreflightError("attempt 001 protocol bundle manifest is invalid")
    paths = (*sorted(protocol_hashes), _ATTEMPT_001_AUTHORITY_SPEC_PATH)
    hashes = {relative: sha256_file(repo_root / relative) for relative in paths}
    return {
        "schema_version": "fieldtrue.protocol-bundle.v1",
        "files": hashes,
        "bundle_sha256": sha256_value(hashes),
    }


def _write_invalidity(
    path: Path,
    *,
    dataset_id: str,
    dataset_lock_hash: str,
    stage: str,
    error: ValueError,
) -> None:
    atomic_write(
        path,
        canonical_json_pretty(
            {
                "schema_version": "fieldtrue.iter000-invalidity.v1",
                "dataset_id": dataset_id,
                "dataset_lock_hash": dataset_lock_hash,
                "stage": stage,
                "verdict": "INVALID",
                "error_type": type(error).__name__,
                "message": str(error)[:500],
            }
        ),
    )


def _iteration_learning(report: ReadinessReport) -> dict[str, object]:
    if report.verdict == "INVALID":
        lessons = [
            "An integrity failure invalidates scientific adjudication rather than weakening it.",
            "No scientific-readiness inference is permitted after an invalidating stop condition.",
            "Invalid results receive the same proof and publication path as other verdicts.",
        ]
    else:
        lessons = [
            "Public data usefulness and scientific sufficiency are separate gates.",
            "Fault-injection metadata must be physically separated from model evidence.",
            "Static fault runs do not supply counterfactual safe-test outcomes.",
        ]
    return {
        "schema_version": "fieldtrue.iteration-learning.v1",
        "iteration_id": "iter000_nasa_adapt_corpus_readiness",
        "verdict": report.verdict,
        "grounded_lessons": lessons,
        "engine_extraction_candidates": [
            "content-addressed source acquisition",
            "typed evidence/truth separation",
            "proof-first result rendering",
        ],
        "engine_construction_authorized": False,
    }


def _finalize_iter000(
    *,
    report: ReadinessReport,
    proof_root: Path,
    dataset_lock_path: Path,
    amendment_contract_path: Path,
    amendment_document_path: Path,
    authority_specification_path: Path | None,
    authority_receipt_path: Path | None,
    evidence_artifacts: dict[str, Path],
    ledger: SignedLedger,
    run_id: str,
    runtime: RuntimeIdentity,
    expected_signer_public_key: Ed25519PublicKey,
    signer_anchor_path: Path,
) -> ReadinessReport:
    proof_dataset_lock = proof_root / "dataset_lock.json"
    atomic_write(proof_dataset_lock, dataset_lock_path.read_bytes())
    proof_amendment_contract = proof_root / "amendment_001.json"
    proof_amendment_document = proof_root / "AMENDMENT_001.md"
    atomic_write(proof_amendment_contract, amendment_contract_path.read_bytes())
    atomic_write(proof_amendment_document, amendment_document_path.read_bytes())
    proof_authority_receipt: Path | None = None
    proof_authority_specification: Path | None = None
    if authority_receipt_path is not None:
        if authority_specification_path is None:
            raise ExperimentFinalizationError(
                "attempt authority receipt has no bound authority specification"
            )
        proof_authority_specification = proof_root / "attempt_authority.json"
        proof_authority_receipt = proof_root / "attempt_authority_consumption.json"
        atomic_write(
            proof_authority_specification,
            authority_specification_path.read_bytes(),
        )
        atomic_write(proof_authority_receipt, authority_receipt_path.read_bytes())
    proof_report = proof_root / "readiness_report.json"
    proof_result = proof_root / "RESULT.md"
    write_readiness_artifacts(report, proof_report, proof_result)

    learning_bytes = canonical_json_pretty(_iteration_learning(report))
    proof_learning = proof_root / "LEARNING.json"
    atomic_write(proof_learning, learning_bytes)
    ledger.append(
        run_id=run_id,
        event_type="readiness-adjudicated",
        payload={
            "verdict": report.verdict,
            "readiness_report_hash": sha256_file(proof_report),
            "result_hash": sha256_file(proof_result),
            "learning_hash": sha256_file(proof_learning),
            "gate_statuses": {gate.gate_id: gate.status.value for gate in report.gates},
        },
        runtime=runtime,
    )

    artifact_paths = {
        "AMENDMENT_001.md": proof_amendment_document,
        "amendment_001.json": proof_amendment_contract,
        "dataset_lock.json": proof_dataset_lock,
        **evidence_artifacts,
        "readiness_report.json": proof_report,
        "RESULT.md": proof_result,
        "LEARNING.json": proof_learning,
    }
    if proof_authority_receipt is not None:
        if proof_authority_specification is None:
            raise ExperimentFinalizationError("attempt authority specification copy is missing")
        artifact_paths["attempt_authority.json"] = proof_authority_specification
        artifact_paths["attempt_authority_consumption.json"] = proof_authority_receipt
    artifact_hashes = {name: sha256_file(path) for name, path in sorted(artifact_paths.items())}
    artifact_bundle_body: dict[str, object] = {
        "schema_version": "fieldtrue.artifact-bundle.v1",
        "run_id": run_id,
        "artifacts": artifact_hashes,
    }
    artifact_bundle = {
        **artifact_bundle_body,
        "bundle_sha256": sha256_value(artifact_bundle_body),
    }
    artifact_bundle_path = proof_root / "artifact_bundle.json"
    atomic_write(artifact_bundle_path, canonical_json_pretty(artifact_bundle))

    ledger_checkpoint = verify_ledger(
        proof_root / "execution_ledger.jsonl",
        proof_root / "execution_ledger.head.json",
        expected_signer_public_key=expected_signer_public_key,
    )
    manifest_body = {
        "schema_version": "fieldtrue.run-manifest.v1",
        "run_id": run_id,
        "runtime": runtime,
        "artifacts": {
            **artifact_hashes,
            "artifact_bundle.json": sha256_file(artifact_bundle_path),
        },
        "ledger_checkpoint": ledger_checkpoint,
        "verdict": report.verdict,
    }
    manifest = {
        **manifest_body,
        "manifest_content_hash": sha256_value(manifest_body),
    }
    manifest_path = proof_root / "run_manifest.json"
    atomic_write(manifest_path, canonical_json_pretty(manifest))
    ledger.append(
        run_id=run_id,
        event_type="run-completed",
        payload={
            "verdict": report.verdict,
            "authorized_next_action": report.authorized_next_action,
            "gpu_hours": 0,
            "cloud_jobs": 0,
            "paid_calls": 0,
            "artifact_bundle_hash": sha256_file(artifact_bundle_path),
            "run_manifest_hash": sha256_file(manifest_path),
        },
        runtime=runtime,
    )
    try:
        verification = verify_iter000_proof_bundle(
            proof_root,
            signer_anchor_path=signer_anchor_path,
            authority_specification_path=authority_specification_path,
        )
    except ProofBundleVerificationError as error:
        raise ExperimentFinalizationError(
            "sealed iter000 proof bundle failed independent verification"
        ) from error
    if verification.verdict != report.verdict:
        raise ExperimentFinalizationError(
            "sealed iter000 proof verdict differs from the producer verdict"
        )
    return report


def run_iter000(repo_root: Path, *, command: tuple[str, ...]) -> ReadinessReport:
    with _exclusive_run_lock(repo_root / ".local" / "locks" / "iter000.lock"):
        return _run_iter000_locked(repo_root, command=command, attempt_id="attempt_000")


def run_iter000_amendment_001(
    repo_root: Path,
    *,
    command: tuple[str, ...],
) -> ReadinessReport:
    with _exclusive_run_lock(repo_root / ".local" / "locks" / "iter000.lock"):
        return _run_iter000_locked(repo_root, command=command, attempt_id="attempt_001")


def _run_iter000_locked(
    repo_root: Path,
    *,
    command: tuple[str, ...],
    attempt_id: str,
) -> ReadinessReport:
    if attempt_id not in {"attempt_000", "attempt_001"}:
        raise ExperimentPreflightError("iteration 000 attempt ID is not authorized")
    from fieldtrue.mission import validate_mission

    experiment_root = repo_root / "experiments" / "iter000_nasa_adapt_corpus_readiness"
    proof_root = experiment_root / "proof" / attempt_id
    if proof_root.is_symlink() or proof_root.exists():
        raise ExperimentAlreadyExecutedError(
            "iteration 000 attempt output root already exists; amendment required for another run"
        )
    authority_specification_path: Path | None = None
    authority_specification: dict[str, Any] | None = None
    authority_receipt_path = repo_root / _ATTEMPT_001_RECEIPT_PATH
    if attempt_id == "attempt_001":
        authority_specification_path, authority_specification = (
            _load_attempt_001_authority_specification(repo_root)
        )
        if tuple(authority_specification["authorized_command"]) != command:
            raise ExperimentPreflightError("attempt 001 command is not authorized")
        authority_directory = authority_receipt_path.parent
        if authority_directory.is_symlink() or (
            authority_directory.exists() and not authority_directory.is_dir()
        ):
            raise ExperimentPreflightError("attempt authority directory must not be linked")
        if authority_receipt_path.is_symlink() or authority_receipt_path.exists():
            raise ExperimentAlreadyExecutedError(
                "iteration 000 attempt 001 authority is already consumed"
            )
    mission_validation = validate_mission(repo_root)
    if not mission_validation.passed:
        failures = [check.check_id for check in mission_validation.checks if not check.passed]
        raise ExperimentPreflightError(f"mission preflight failed: {', '.join(failures)}")
    runtime = collect_runtime_identity(repo_root, command=command, require_clean=True)
    run_id = f"iter000-{attempt_id}-{runtime.git_commit[:12]}"
    key = load_or_create_signing_key(repo_root / ".local" / "keys" / "iter000.ed25519")
    anchor = load_signer_anchor(repo_root / "protocol" / "trust" / "iter000_signer_anchor.json")
    signer_anchor_path = repo_root / "protocol" / "trust" / "iter000_signer_anchor.json"
    if key.verify_key.encode().hex() != anchor.signer_public_key:
        raise ExperimentPreflightError("local execution key does not match the pinned signer")
    if attempt_id == "attempt_001":
        if authority_specification is None:
            raise ExperimentPreflightError("attempt 001 authority specification was not loaded")
        authority_signer = authority_specification["signer_anchor"]
        if (
            not isinstance(authority_signer, dict)
            or authority_signer.get("signer_public_key") != anchor.signer_public_key
        ):
            raise ExperimentPreflightError(
                "attempt 001 authority signer does not match the pinned signer"
            )
    authority_receipt_hash: str | None = None
    if attempt_id == "attempt_001":
        if authority_specification_path is None or authority_specification is None:
            raise ExperimentPreflightError("attempt 001 authority specification was not loaded")
        authority_receipt_path, authority_receipt_hash = _write_attempt_001_authority_consumption(
            repo_root,
            run_id=run_id,
            runtime=runtime,
            signing_key=key,
            signer_public_key=anchor.signer_public_key,
            authority_specification_path=authority_specification_path,
            authority_specification=authority_specification,
        )
    ledger = SignedLedger(
        proof_root / "execution_ledger.jsonl",
        proof_root / "execution_ledger.head.json",
        key,
    )
    run_started_payload: dict[str, object] = {
        "hypothesis": "experiments/iter000_nasa_adapt_corpus_readiness/HYPOTHESIS.md",
        "protocol_bundle": _protocol_bundle(repo_root),
        "gpu_authorized": False,
        "cloud_authorized": False,
        "live_action_authorized": False,
    }
    if authority_receipt_hash is not None:
        run_started_payload["attempt_authority_consumption_receipt_hash"] = authority_receipt_hash
    ledger.append(
        run_id=run_id,
        event_type="run-started",
        payload=run_started_payload,
        runtime=runtime,
    )
    try:
        lock_path = repo_root / "protocol" / "datasets" / "nasa_adapt_v1.json"
        amendment_contract_path = repo_root / "protocol" / "amendments" / "iter000_001.json"
        amendment_document_path = experiment_root / "AMENDMENT_001.md"
        lock = load_adapt_lock(lock_path)
        raw_root = repo_root / "data" / "raw" / lock.dataset_id
        derived_root = repo_root / "data" / "derived" / lock.dataset_id
        try:
            resource_receipts = fetch_adapt_dataset(lock, raw_root)
        except ValueError as error:
            proof_root.mkdir(parents=True, exist_ok=True)
            invalidity_path = proof_root / "invalidity.json"
            _write_invalidity(
                invalidity_path,
                dataset_id=lock.dataset_id,
                dataset_lock_hash=sha256_file(lock_path),
                stage="source-integrity",
                error=error,
            )
            ledger.append(
                run_id=run_id,
                event_type="source-invalid",
                payload={
                    "invalidity_hash": sha256_file(invalidity_path),
                    "error_type": type(error).__name__,
                },
                runtime=runtime,
            )
            report = invalid_readiness_report(
                dataset_id=lock.dataset_id,
                failed_gate_id="source-integrity",
                error_type=type(error).__name__,
                error_message=str(error)[:500],
            )
            return _finalize_iter000(
                report=report,
                proof_root=proof_root,
                dataset_lock_path=lock_path,
                amendment_contract_path=amendment_contract_path,
                amendment_document_path=amendment_document_path,
                authority_specification_path=authority_specification_path,
                authority_receipt_path=(
                    authority_receipt_path if authority_receipt_hash is not None else None
                ),
                evidence_artifacts={"invalidity.json": invalidity_path},
                ledger=ledger,
                run_id=run_id,
                runtime=runtime,
                expected_signer_public_key=anchor.signer_public_key,
                signer_anchor_path=signer_anchor_path,
            )
        ledger.append(
            run_id=run_id,
            event_type="sources-verified",
            payload={
                "dataset_id": lock.dataset_id,
                "dataset_lock_hash": sha256_file(lock_path),
                "resources": [receipt.model_dump(mode="json") for receipt in resource_receipts],
                "network_source_only": True,
                "cost_usd": "0",
            },
            runtime=runtime,
        )
        try:
            ingestion = ingest_adapt_dataset(lock, raw_root, derived_root, resource_receipts)
        except ValueError as error:
            proof_root.mkdir(parents=True, exist_ok=True)
            invalidity_path = proof_root / "invalidity.json"
            _write_invalidity(
                invalidity_path,
                dataset_id=lock.dataset_id,
                dataset_lock_hash=sha256_file(lock_path),
                stage="parser-integrity",
                error=error,
            )
            ledger.append(
                run_id=run_id,
                event_type="ingestion-invalid",
                payload={
                    "invalidity_hash": sha256_file(invalidity_path),
                    "error_type": type(error).__name__,
                },
                runtime=runtime,
            )
            report = invalid_readiness_report(
                dataset_id=lock.dataset_id,
                failed_gate_id="parser-integrity",
                error_type=type(error).__name__,
                error_message=str(error)[:500],
                passed_gate_ids=("source-integrity",),
            )
            return _finalize_iter000(
                report=report,
                proof_root=proof_root,
                dataset_lock_path=lock_path,
                amendment_contract_path=amendment_contract_path,
                amendment_document_path=amendment_document_path,
                authority_specification_path=authority_specification_path,
                authority_receipt_path=(
                    authority_receipt_path if authority_receipt_hash is not None else None
                ),
                evidence_artifacts={"invalidity.json": invalidity_path},
                ledger=ledger,
                run_id=run_id,
                runtime=runtime,
                expected_signer_public_key=anchor.signer_public_key,
                signer_anchor_path=signer_anchor_path,
            )
        proof_root.mkdir(parents=True, exist_ok=True)
        atomic_write(proof_root / "ingestion_receipt.json", ingestion.receipt_path.read_bytes())
        atomic_write(proof_root / "coverage.json", ingestion.coverage_path.read_bytes())
        atomic_write(
            proof_root / "model_evidence_manifest.jsonl",
            ingestion.evidence_manifest_path.read_bytes(),
        )
        atomic_write(
            proof_root / "truth_manifest.jsonl",
            ingestion.truth_manifest_path.read_bytes(),
            mode=0o600,
        )
        ledger.append(
            run_id=run_id,
            event_type="dataset-ingested",
            payload={
                "ingestion_receipt_hash": sha256_file(proof_root / "ingestion_receipt.json"),
                "coverage_hash": sha256_file(proof_root / "coverage.json"),
                "model_evidence_manifest_hash": sha256_file(
                    proof_root / "model_evidence_manifest.jsonl"
                ),
                "evidence_manifest_hash": ingestion.receipt.evidence_manifest_sha256,
                "truth_manifest_hash": ingestion.receipt.truth_manifest_sha256,
                "truth_separation_passed": ingestion.receipt.truth_separation_passed,
            },
            runtime=runtime,
        )
        report = audit_adapt_readiness(lock, ingestion)
        return _finalize_iter000(
            report=report,
            proof_root=proof_root,
            dataset_lock_path=lock_path,
            amendment_contract_path=amendment_contract_path,
            amendment_document_path=amendment_document_path,
            authority_specification_path=authority_specification_path,
            authority_receipt_path=(
                authority_receipt_path if authority_receipt_hash is not None else None
            ),
            evidence_artifacts={
                "coverage.json": proof_root / "coverage.json",
                "ingestion_receipt.json": proof_root / "ingestion_receipt.json",
                "model_evidence_manifest.jsonl": (proof_root / "model_evidence_manifest.jsonl"),
                "truth_manifest.jsonl": proof_root / "truth_manifest.jsonl",
            },
            ledger=ledger,
            run_id=run_id,
            runtime=runtime,
            expected_signer_public_key=anchor.signer_public_key,
            signer_anchor_path=signer_anchor_path,
        )
    except ExperimentFinalizationError:
        raise
    except Exception as error:
        ledger.append(
            run_id=run_id,
            event_type="run-failed",
            payload={"error_type": type(error).__name__, "message": str(error)[:500]},
            runtime=runtime,
        )
        raise
