"""Independent verification for the frozen iteration 000 proof bundle."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, NoReturn, TypeVar, cast

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from pydantic import BaseModel, ConfigDict, ValidationError

from fieldtrue.adapters.adapt import (
    AdaptCoverageReport,
    AdaptDatasetLock,
    AdaptIngestionReceipt,
)
from fieldtrue.canonical import (
    canonical_json,
    canonical_json_pretty,
    sha256_bytes,
    sha256_file,
    sha256_value,
)
from fieldtrue.domain import GateStatus, Identifier, ReadinessReport, Sha256
from fieldtrue.readiness import audit_adapt_proof_readiness, render_readiness_result
from fieldtrue.receipts import (
    LedgerEvent,
    LedgerVerification,
    LedgerVerificationError,
    SignerAnchor,
    verify_ledger,
)
from fieldtrue.runtime import RuntimeIdentity

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


def _canonical(value: Any, data: bytes, label: str) -> None:
    if canonical_json_pretty(value) != data:
        _fail(f"{label} is not canonical pretty JSON")


def _model(model: type[_ModelT], value: Any, label: str) -> _ModelT:
    try:
        return model.model_validate(value)
    except ValidationError as error:
        raise ProofBundleVerificationError(f"{label} violates its typed schema") from error


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
    _canonical(dataset_lock, dataset_lock_data, "dataset lock")
    if actual_hashes["dataset_lock.json"] != protocol_files[_DATASET_PROTOCOL_PATH]:
        _fail("proof-local dataset lock differs from the signed protocol bundle")
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
