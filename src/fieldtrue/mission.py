"""Repository-level mission invariant validator."""

from __future__ import annotations

import ast
import json
import re
import shutil
import ssl
import subprocess
import sys
import tomllib
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as distribution_version
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import certifi
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from pydantic import BaseModel, ConfigDict

from fieldtrue.adapters import adapt as adapt_adapter
from fieldtrue.adapters.adapt import load_adapt_lock
from fieldtrue.canonical import canonical_json, canonical_json_pretty, sha256_bytes, sha256_value
from fieldtrue.domain import ClaimRecord
from fieldtrue.memory import load_memory_records, verify_memory
from fieldtrue.receipts import (
    LedgerEvent,
    LedgerVerificationError,
    load_signer_anchor,
    verify_ledger,
)
from fieldtrue.schemas import verify_schemas

_GIT_OBJECT_ID_PATTERN = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_REQUIRED_GATE_CONTROLS = {
    "pre_registered_rejection_condition",
    "positive_control",
    "negative_control_or_placebo",
    "executable_sensitivity_test",
    "sealed_control_result",
}
_ITER000_GATE_FAILURE_CLASSES = {
    "source-integrity": "invalid",
    "parser-integrity": "invalid",
    "truth-separation": "invalid",
    "minimum-count": "blocked",
    "ambiguity": "blocked",
    "discriminating-action": "blocked",
    "transfer-support": "blocked",
    "evidence-usefulness": "blocked",
}
_PUBLICATION_ANCHOR_ID = "publication-transition"
_PUBLICATION_LEDGER_SCOPE = "publication-gates"
_ITER000_ID = "iter000_nasa_adapt_corpus_readiness"
_AMENDMENT_001_PATH = "protocol/amendments/iter000_001.json"
_AMENDMENT_001_DOCUMENT_PATH = f"experiments/{_ITER000_ID}/AMENDMENT_001.md"
_ATTEMPT_000_PROOF_PATH = f"experiments/{_ITER000_ID}/proof/attempt_000"
_ATTEMPT_000_LEDGER_PATH = f"{_ATTEMPT_000_PROOF_PATH}/execution_ledger.jsonl"
_ATTEMPT_000_HEAD_PATH = f"{_ATTEMPT_000_PROOF_PATH}/execution_ledger.head.json"
_ITER000_ANCHOR_PATH = "protocol/trust/iter000_signer_anchor.json"
_ITER000_DATASET_PATH = "protocol/datasets/nasa_adapt_v1.json"
_ITER000_GATE_CONTROL_PATH = "protocol/gate_controls/v1.json"
_ITER000_HYPOTHESIS_PATH = f"experiments/{_ITER000_ID}/HYPOTHESIS.md"
_ITER000_ATTEMPT_001_AUTHORITY_PATH = "protocol/attempt_authorities/iter000_001.json"
_ITER000_ATTEMPT_001_RECEIPT_PATH = (
    f"experiments/{_ITER000_ID}/authority/attempt_001_consumption.json"
)
_ITER000_TRIGGER_COMMIT = "2fb078a1cac5f76f251ab49e0368ae0ea3e8da2e"
_ITER000_ATTEMPT_000_HEAD = "acf079ecb5b989d3b5615d01bed4141fbd1d9c95436baabc65cfff707ff914d9"
_ITER000_ATTEMPT_000_RUN_ID = "iter000-2fb078a1cac5"
_ITER000_ATTEMPT_000_FAILURE = (
    "<urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
    "unable to get local issuer certificate (_ssl.c:1000)>"
)
_ITER000_CERTIFI_VERSION = "2026.6.17"
_ITER000_CA_BUNDLE_SHA256 = "bbc7e9c01d7551bb8a159b5dedd989b8ee3ce105aff522b68eb1b01bf854cab0"
_ITER000_TLS_CONSTRAINTS: dict[str, object] = {
    "bypass_forbidden": True,
    "ca_bundle_sha256": _ITER000_CA_BUNDLE_SHA256,
    "certificate_verification": "required",
    "hostname_verification": "required",
    "minimum_tls_version": "TLSv1.2",
    "trust_store": "certifi",
    "trust_store_version": _ITER000_CERTIFI_VERSION,
}
_ITER000_FROZEN_HASHES = {
    _ATTEMPT_000_LEDGER_PATH: "c84327a7c15e48e7169711b7b84aa7167fa170ab3b735993b3ff5b224d7e5982",
    _ATTEMPT_000_HEAD_PATH: "332878b131ab2c5a0c024854f0a43a552c0f8b0a36330d18a0b3b405b89bfa07",
    _ITER000_ANCHOR_PATH: "7174bedb14de9f6cc7bd178a2b70a71f75baa04d1291004dbfaa6304fb701022",
    _ITER000_DATASET_PATH: "884c1ff5daf60323437ad1d16efb01acb3e769ce71eade62fcde966bfe0a4367",
    _ITER000_HYPOTHESIS_PATH: "b5f18e02b54a137aa966ce70a3f89f2616167992cc2583508f2b3b0403d205d5",
}
_ITER000_ATTEMPT_001_PROTOCOL_PATHS = frozenset(
    {
        "PREREGISTRATION.md",
        "claims/registry.jsonl",
        _AMENDMENT_001_DOCUMENT_PATH,
        _ITER000_HYPOTHESIS_PATH,
        "mission/contract.json",
        "mission/loop.json",
        "mission/name.json",
        _AMENDMENT_001_PATH,
        "protocol/baselines/v1.json",
        _ITER000_DATASET_PATH,
        _ITER000_GATE_CONTROL_PATH,
        _ITER000_ANCHOR_PATH,
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
    }
)
# These administrative files may differ from the trigger, but the authority manifest still
# binds their exact HEAD bytes. This avoids self-hashing mission policy in source constants.
_ITER000_ATTEMPT_001_RECOVERY_PATHS = frozenset(
    {
        _AMENDMENT_001_DOCUMENT_PATH,
        _AMENDMENT_001_PATH,
        _ITER000_GATE_CONTROL_PATH,
        "pyproject.toml",
        "src/fieldtrue/cli.py",
        "src/fieldtrue/mission.py",
        "src/fieldtrue/verification.py",
        "uv.lock",
    }
)
_ITER000_ATTEMPT_001_AUTHORIZED_SOURCE_HASHES = {
    "src/fieldtrue/adapters/adapt.py": (
        "586d44ad6fa45cca45dfd70bb9ae6f6c4a21e9eab47873ba5e6809c5e2a1dcfc",
        "ccb0865cf045373216b072ae6f9705edb4013992e19cb54903d8e13df1c1587e",
    ),
    "src/fieldtrue/experiment.py": (
        "25dea0b8dbc521f892fc20bc06e177cf00987dc90acb1e587d97dc245b00f506",
        "a2f05e5dbeeb5a57d99696761b449757a2a2573dcbb91cb670ee39303804bb1f",
    ),
}
_ITER000_SIGNER_PUBLIC_KEY = "0d5d5313b054a05978811e3f56195d4e806b50924af05cb9c811dca8c1767646"
_GATE_CONTROL_SEALED_PATHS = (
    "src/fieldtrue/adapters/adapt.py",
    "src/fieldtrue/domain.py",
    "src/fieldtrue/mission.py",
    "src/fieldtrue/readiness.py",
    "tests/helpers.py",
    "tests/unit/test_readiness.py",
)


class ValidationCheck(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    check_id: str
    passed: bool
    detail: str


class MissionValidation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    passed: bool
    checks: tuple[ValidationCheck, ...]


def _check(check_id: str, condition: bool, detail: str) -> ValidationCheck:
    return ValidationCheck(check_id=check_id, passed=condition, detail=detail)


def _json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _claims(path: Path) -> list[ClaimRecord]:
    claims: list[ClaimRecord] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            claims.append(ClaimRecord.model_validate_json(line))
        except ValueError as error:
            raise ValueError(f"invalid claim registry line {line_number}") from error
    return claims


def _gate_controls_valid(loop: dict[str, Any]) -> bool:
    policy = loop.get("gate_falsification_policy")
    if not isinstance(policy, dict):
        return False
    requirements = policy.get("requirements")
    return (
        policy.get("scope") == "every_claim_bearing_gate"
        and isinstance(requirements, list)
        and all(isinstance(requirement, str) for requirement in requirements)
        and len(requirements) == len(set(requirements))
        and set(requirements) == _REQUIRED_GATE_CONTROLS
        and policy.get("rule")
        == "A gate is invalid until a deliberately broken or placebo artifact is rejected."
    )


def _pytest_node(repo_root: Path, node_id: object) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    if not isinstance(node_id, str):
        return None
    parts = node_id.split("::")
    if len(parts) != 2 or not parts[1].startswith("test_"):
        return None
    relative, function_name = parts
    pure = PurePosixPath(relative)
    if (
        pure.is_absolute()
        or ".." in pure.parts
        or not pure.parts
        or pure.parts[0] != "tests"
        or pure.suffix != ".py"
        or pure.as_posix() != relative
    ):
        return None
    path = repo_root.joinpath(*pure.parts)
    try:
        module = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
    except (OSError, SyntaxError, UnicodeError):
        return None
    for node in module.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function_name:
            return node
    return None


def _pytest_node_exists(repo_root: Path, node_id: object) -> bool:
    return _pytest_node(repo_root, node_id) is not None


def _control_node_is_substantive(
    repo_root: Path,
    node_id: object,
    *,
    gate_id: str,
    role: str,
    expected_status: str,
) -> bool:
    node = _pytest_node(repo_root, node_id)
    if node is None or not isinstance(node_id, str):
        return False
    expected_name = f"test_{gate_id.replace('-', '_')}_{role}_control"
    if node.name != expected_name:
        return False
    has_assertion = any(isinstance(child, ast.Assert) for child in ast.walk(node))
    names_gate = any(
        isinstance(child, ast.Constant) and child.value == gate_id for child in ast.walk(node)
    )
    checks_status = any(
        isinstance(child, ast.Attribute)
        and isinstance(child.value, ast.Name)
        and child.value.id == "GateStatus"
        and child.attr == expected_status.upper()
        for child in ast.walk(node)
    )
    calls_adjudicator = any(
        isinstance(child, ast.Call)
        and isinstance(child.func, ast.Name)
        and child.func.id == "audit_adapt_readiness"
        for child in ast.walk(node)
    )
    return has_assertion and names_gate and checks_status and calls_adjudicator


def _gate_control_set_hash(
    repo_root: Path,
    *,
    iteration_id: str,
    controls: list[dict[str, Any]],
    sealed_paths: tuple[str, ...],
) -> str | None:
    file_hashes: dict[str, str] = {}
    for relative in sealed_paths:
        path = repo_root / relative
        if path.is_symlink() or not path.is_file():
            return None
        file_hashes[relative] = sha256_bytes(path.read_bytes())
    return sha256_value(
        {
            "iteration_id": iteration_id,
            "controls": controls,
            "files": file_hashes,
        }
    )


def _verify_gate_control_registry(repo_root: Path, path: Path) -> tuple[bool, str]:
    try:
        registry = _json(path)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return False, f"Gate control registry is unreadable: {type(error).__name__}."
    controls = registry.get("controls")
    execution_seal = registry.get("execution_seal")
    if (
        set(registry) != {"schema_version", "iteration_id", "controls", "execution_seal"}
        or registry.get("schema_version") != "fieldtrue.gate-control-registry.v1"
        or registry.get("iteration_id") != "iter000_nasa_adapt_corpus_readiness"
        or not isinstance(controls, list)
        or not isinstance(execution_seal, dict)
    ):
        return False, "Gate control registry identity or structure is invalid."
    by_gate: dict[str, dict[str, Any]] = {}
    for control in controls:
        if (
            not isinstance(control, dict)
            or set(control) != {"gate_id", "failure_class", "positive_control", "negative_control"}
            or not isinstance(control.get("gate_id"), str)
        ):
            return False, "Gate control registry contains an invalid control record."
        gate_id = control["gate_id"]
        if gate_id in by_gate:
            return False, f"Gate control registry duplicates {gate_id}."
        by_gate[gate_id] = control
    if set(by_gate) != set(_ITER000_GATE_FAILURE_CLASSES):
        return False, "Gate control registry does not cover the exact iteration-000 gate set."
    failures: list[str] = []
    node_ids: list[str] = []
    for gate_id, failure_class in _ITER000_GATE_FAILURE_CLASSES.items():
        control = by_gate[gate_id]
        if control.get("failure_class") != failure_class:
            failures.append(f"{gate_id}: failure class")
        for role in ("positive_control", "negative_control"):
            node_id = control.get(role)
            if not _control_node_is_substantive(
                repo_root,
                node_id,
                gate_id=gate_id,
                role=role.removesuffix("_control"),
                expected_status="pass" if role == "positive_control" else failure_class,
            ):
                failures.append(f"{gate_id}: {role}")
            elif isinstance(node_id, str):
                node_ids.append(node_id)
        if control.get("positive_control") == control.get("negative_control"):
            failures.append(f"{gate_id}: controls are not distinct")
    if len(node_ids) != len(set(node_ids)):
        failures.append("control node IDs are not globally unique")
    if failures:
        return False, "Gate control registry failures: " + "; ".join(failures)
    expected_seal_keys = {
        "schema_version",
        "runner",
        "expected_exit_code",
        "sealed_paths",
        "control_set_sha256",
        "passing_result_sha256",
    }
    sealed_paths = execution_seal.get("sealed_paths")
    if (
        set(execution_seal) != expected_seal_keys
        or execution_seal.get("schema_version") != "fieldtrue.gate-control-execution-seal.v1"
        or execution_seal.get("runner") != "python -m pytest"
        or execution_seal.get("expected_exit_code") != 0
        or not isinstance(sealed_paths, list)
        or tuple(sealed_paths) != _GATE_CONTROL_SEALED_PATHS
    ):
        return False, "Gate control execution seal is malformed or has incomplete source coverage."
    control_set_hash = _gate_control_set_hash(
        repo_root,
        iteration_id=registry["iteration_id"],
        controls=controls,
        sealed_paths=tuple(sealed_paths),
    )
    if control_set_hash is None or execution_seal.get("control_set_sha256") != control_set_hash:
        return False, "Gate control source seal does not match the executable control set."
    try:
        execution = subprocess.run(  # noqa: S603 - node IDs and paths are validated above
            [sys.executable, "-m", "pytest", "-q", *node_ids],
            cwd=repo_root,
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return False, f"Gate control execution failed to run: {type(error).__name__}."
    result = {
        "schema_version": "fieldtrue.gate-control-execution-result.v1",
        "control_set_sha256": control_set_hash,
        "executed_nodes": node_ids,
        "exit_code": execution.returncode,
        "outcome": "passed" if execution.returncode == 0 else "failed",
    }
    result_hash = sha256_value(result)
    if execution.returncode != 0 or execution_seal.get("passing_result_sha256") != result_hash:
        output = (execution.stdout + execution.stderr).strip()[-500:]
        return False, f"Gate controls did not reproduce their sealed passing result: {output}"
    return (
        True,
        f"Executed and verified {len(node_ids)} distinct controls against the sealed result.",
    )


def _root_commit(repo_root: Path) -> str:
    git = shutil.which("git")
    if git is None:
        raise FileNotFoundError("git is required for mission validation")
    root_commit = subprocess.run(  # noqa: S603 - fixed executable and literal arguments
        [git, "rev-list", "--max-parents=0", "HEAD"],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if re.fullmatch(r"[0-9a-f]{40}", root_commit) is None:
        raise ValueError("git returned an invalid root commit")
    return root_commit


def _first_commit_files(repo_root: Path) -> list[str]:
    git = shutil.which("git")
    if git is None:
        raise FileNotFoundError("git is required for mission validation")
    root_commit = _root_commit(repo_root)
    output = subprocess.run(  # noqa: S603 - root_commit is validated hexadecimal Git output
        [git, "show", "--pretty=", "--name-only", root_commit],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return sorted(line for line in output.splitlines() if line)


def _root_preregistration_bytes(repo_root: Path, relative_path: str) -> bytes:
    git = shutil.which("git")
    if git is None:
        raise FileNotFoundError("git is required for mission validation")
    return subprocess.run(  # noqa: S603 - fixed Git command and validated root commit
        [git, "show", f"{_root_commit(repo_root)}:{relative_path}"],
        cwd=repo_root,
        check=True,
        capture_output=True,
    ).stdout


def _git_commit_resolves(repo_root: Path, git: str, object_id: str) -> bool:
    if _GIT_OBJECT_ID_PATTERN.fullmatch(object_id) is None:
        return False
    result = subprocess.run(  # noqa: S603 - Git path and object ID are validated
        [git, "cat-file", "-e", f"{object_id}^{{commit}}"],
        cwd=repo_root,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def _git_blob_at_path(
    repo_root: Path,
    git: str,
    commit: str,
    relative_path: str,
) -> bytes | None:
    if _GIT_OBJECT_ID_PATTERN.fullmatch(commit) is None:
        return None
    pure_path = PurePosixPath(relative_path)
    if pure_path.is_absolute() or ".." in pure_path.parts or pure_path.as_posix() != relative_path:
        return None
    tree_result = subprocess.run(  # noqa: S603 - Git path, commit, and literal path are validated
        [git, "ls-tree", "-z", commit, "--", f":(literal){relative_path}"],
        cwd=repo_root,
        check=False,
        capture_output=True,
    )
    entries = [entry for entry in tree_result.stdout.split(b"\0") if entry]
    if tree_result.returncode != 0 or len(entries) != 1:
        return None
    metadata, separator, discovered_path = entries[0].partition(b"\t")
    try:
        metadata_parts = metadata.decode("ascii").split()
        path_matches = discovered_path.decode("utf-8") == relative_path
    except UnicodeDecodeError:
        return None
    if separator != b"\t" or len(metadata_parts) != 3 or not path_matches:
        return None
    _, object_type, object_id = metadata_parts
    if object_type != "blob" or _GIT_OBJECT_ID_PATTERN.fullmatch(object_id) is None:
        return None
    blob_result = subprocess.run(  # noqa: S603 - Git path and object ID are validated
        [git, "cat-file", "blob", object_id],
        cwd=repo_root,
        check=False,
        capture_output=True,
    )
    return blob_result.stdout if blob_result.returncode == 0 else None


def _verify_memory_git_anchors(repo_root: Path, memory_path: Path) -> tuple[bool, str]:
    git = shutil.which("git")
    if git is None:
        return False, "Research memory Git anchors cannot verify because Git is unavailable."
    records = load_memory_records(memory_path)
    failures: list[str] = []
    commit_results: dict[str, bool] = {}

    def commit_resolves(object_id: str) -> bool:
        if object_id not in commit_results:
            commit_results[object_id] = _git_commit_resolves(repo_root, git, object_id)
        return commit_results[object_id]

    for record in records:
        if not commit_resolves(record.source_commit):
            failures.append(f"{record.event_id}: source_commit is not a Git commit")
        for index, evidence in enumerate(record.evidence):
            if urlsplit(evidence.uri).scheme:
                continue
            evidence_label = f"{record.event_id}: evidence[{index}] {evidence.uri}"
            if evidence.git_commit is None or not commit_resolves(evidence.git_commit):
                failures.append(f"{evidence_label}: git_commit is not a Git commit")
                continue
            blob = _git_blob_at_path(repo_root, git, evidence.git_commit, evidence.uri)
            if blob is None:
                failures.append(f"{evidence_label}: path is not a historical Git blob")
                continue
            if evidence.sha256 is not None and sha256_bytes(blob) != evidence.sha256:
                failures.append(f"{evidence_label}: sha256 does not match the historical Git blob")

    if failures:
        return False, "Research memory Git anchors failed: " + "; ".join(failures)
    event_label = "event" if len(records) == 1 else "events"
    return True, f"Research memory Git anchors verify ({len(records)} {event_label})."


def _safe_relative_path(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    pure = PurePosixPath(value)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts or pure.as_posix() != value:
        return None
    return value


def _git_is_ancestor(repo_root: Path, git: str, ancestor: str, descendant: str) -> bool:
    if (
        _GIT_OBJECT_ID_PATTERN.fullmatch(ancestor) is None
        or _GIT_OBJECT_ID_PATTERN.fullmatch(descendant) is None
    ):
        return False
    result = subprocess.run(  # noqa: S603 - Git path and object IDs are validated
        [git, "merge-base", "--is-ancestor", ancestor, descendant],
        cwd=repo_root,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def _expected_iteration_amendment_001(document_sha256: str) -> dict[str, Any]:
    return {
        "amendment_document": {
            "path": _AMENDMENT_001_DOCUMENT_PATH,
            "sha256": document_sha256,
        },
        "amendment_id": "iter000_001",
        "frozen_inputs": {
            "dataset_lock": {
                "path": _ITER000_DATASET_PATH,
                "sha256": _ITER000_FROZEN_HASHES[_ITER000_DATASET_PATH],
            },
            "hypothesis": {
                "path": _ITER000_HYPOTHESIS_PATH,
                "sha256": _ITER000_FROZEN_HASHES[_ITER000_HYPOTHESIS_PATH],
            },
        },
        "iteration_id": _ITER000_ID,
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
            "tls": _ITER000_TLS_CONSTRAINTS,
        },
        "schema_version": "fieldtrue.iter000-amendment.v1",
        "status": "authorized",
        "trigger_attempt": {
            "artifacts": {
                "ledger": {
                    "path": _ATTEMPT_000_LEDGER_PATH,
                    "sha256": _ITER000_FROZEN_HASHES[_ATTEMPT_000_LEDGER_PATH],
                },
                "ledger_head": {
                    "path": _ATTEMPT_000_HEAD_PATH,
                    "sha256": _ITER000_FROZEN_HASHES[_ATTEMPT_000_HEAD_PATH],
                },
                "signer_anchor": {
                    "path": _ITER000_ANCHOR_PATH,
                    "sha256": _ITER000_FROZEN_HASHES[_ITER000_ANCHOR_PATH],
                },
            },
            "attempt_id": "attempt_000",
            "expected_event_types": ["run-started", "run-failed"],
            "expected_head_hash": _ITER000_ATTEMPT_000_HEAD,
            "expected_run_id": _ITER000_ATTEMPT_000_RUN_ID,
            "failure": {
                "error_type": "URLError",
                "message": _ITER000_ATTEMPT_000_FAILURE,
            },
            "scientific_effect": {
                "accepted_data": False,
                "result_artifact": False,
                "scientific_verdict": False,
            },
            "triggering_git_commit": _ITER000_TRIGGER_COMMIT,
        },
    }


def _qualified_ast_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _qualified_ast_name(node.value)
        return f"{prefix}.{node.attr}" if prefix is not None else None
    return None


def _adapt_tls_source_is_verified(path: Path) -> bool:
    try:
        module = ast.parse(path.read_text(encoding="utf-8"), filename=path.as_posix())
    except (OSError, SyntaxError, UnicodeError):
        return False
    functions = {
        node.name: node
        for node in module.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    context_function = functions.get("_verified_tls_context")
    download_function = functions.get("_download_resource")
    if context_function is None or download_function is None:
        return False

    context_calls = [
        node
        for node in ast.walk(context_function)
        if isinstance(node, ast.Call)
        and _qualified_ast_name(node.func) == "ssl.create_default_context"
    ]
    certifi_context = False
    for call in context_calls:
        cafile = next((item.value for item in call.keywords if item.arg == "cafile"), None)
        if (
            isinstance(cafile, ast.Call)
            and not cafile.args
            and not cafile.keywords
            and _qualified_ast_name(cafile.func) == "certifi.where"
        ):
            certifi_context = True
    urlopen_calls = [
        node
        for node in ast.walk(download_function)
        if isinstance(node, ast.Call) and _qualified_ast_name(node.func) == "urllib.request.urlopen"
    ]
    verified_download = False
    if len(urlopen_calls) == 1:
        context = next(
            (item.value for item in urlopen_calls[0].keywords if item.arg == "context"),
            None,
        )
        verified_download = (
            isinstance(context, ast.Call)
            and not context.args
            and not context.keywords
            and _qualified_ast_name(context.func) == "_verified_tls_context"
        )

    forbidden_names = {
        "CERT_NONE",
        "PYTHONHTTPSVERIFY",
        "_create_unverified_context",
        "create_unverified_context",
    }
    forbidden_literals = {
        "--insecure",
        "PYTHONHTTPSVERIFY",
    }
    bypass_present = any(
        (
            isinstance(node, (ast.Name, ast.Attribute))
            and (_qualified_ast_name(node) or "").split(".")[-1] in forbidden_names
        )
        or (isinstance(node, ast.Constant) and node.value in forbidden_literals)
        or (
            isinstance(node, ast.keyword)
            and node.arg in {"verify", "check_hostname"}
            and isinstance(node.value, ast.Constant)
            and node.value.value is False
        )
        or (
            isinstance(node, (ast.Assign, ast.AnnAssign))
            and isinstance(node.value, ast.Constant)
            and node.value.value is False
            and any(
                isinstance(target, ast.Attribute) and target.attr == "check_hostname"
                for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
            )
        )
        for node in ast.walk(module)
    )
    return certifi_context and verified_download and not bypass_present


def _verified_tls_runtime_active() -> bool:
    try:
        certifi_path = Path(certifi.where())
        if certifi_path.is_symlink() or not certifi_path.is_file():
            return False
        certifi_bundle_hash = sha256_bytes(certifi_path.read_bytes())
        actual = adapt_adapter._verified_tls_context()
        expected = ssl.create_default_context(cafile=certifi.where())
        actual_authorities = {
            sha256_bytes(certificate) for certificate in actual.get_ca_certs(binary_form=True)
        }
        expected_authorities = {
            sha256_bytes(certificate) for certificate in expected.get_ca_certs(binary_form=True)
        }
    except (OSError, PackageNotFoundError, ValueError, ssl.SSLError):
        return False
    return (
        distribution_version("certifi") == _ITER000_CERTIFI_VERSION
        and certifi_bundle_hash == _ITER000_CA_BUNDLE_SHA256
        and isinstance(actual, ssl.SSLContext)
        and actual.verify_mode == ssl.CERT_REQUIRED
        and actual.check_hostname is True
        and actual.minimum_version >= ssl.TLSVersion.TLSv1_2
        and bool(actual_authorities)
        and actual_authorities == expected_authorities
    )


def _certifi_dependency_is_locked(repo_root: Path) -> bool:
    try:
        project = tomllib.loads((repo_root / "pyproject.toml").read_text(encoding="utf-8"))
        lock = tomllib.loads((repo_root / "uv.lock").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return False
    dependencies = project.get("project", {}).get("dependencies", [])
    packages = lock.get("package", [])
    fieldtrue_package = next(
        (
            package
            for package in packages
            if isinstance(package, dict) and package.get("name") == "fieldtrue"
        ),
        None,
    )
    locked_dependencies = (
        fieldtrue_package.get("dependencies", []) if isinstance(fieldtrue_package, dict) else []
    )
    certifi_package = next(
        (
            package
            for package in packages
            if isinstance(package, dict) and package.get("name") == "certifi"
        ),
        None,
    )
    return (
        "certifi>=2026.6.17,<2027" in dependencies
        and isinstance(certifi_package, dict)
        and certifi_package.get("version") == _ITER000_CERTIFI_VERSION
        and any(
            isinstance(dependency, dict) and dependency.get("name") == "certifi"
            for dependency in locked_dependencies
        )
    )


def _git_tree_paths(repo_root: Path, git: str, commit: str, prefix: str) -> set[str] | None:
    result = subprocess.run(  # noqa: S603 - fixed Git operation and validated commit
        [git, "ls-tree", "-r", "-z", "--name-only", commit, "--", f":(literal){prefix}"],
        cwd=repo_root,
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        return None
    paths: set[str] = set()
    for encoded in result.stdout.split(b"\0"):
        if not encoded:
            continue
        try:
            relative = encoded.decode("utf-8")
        except UnicodeDecodeError:
            return None
        if _safe_relative_path(relative) is None or not relative.startswith(f"{prefix}/"):
            return None
        paths.add(relative)
    return paths


def _working_source_paths(repo_root: Path) -> set[str] | None:
    source_root = repo_root / "src" / "fieldtrue"
    if source_root.is_symlink() or not source_root.is_dir():
        return None
    paths: set[str] = set()
    try:
        candidates = tuple(source_root.rglob("*"))
    except OSError:
        return None
    for candidate in candidates:
        relative = candidate.relative_to(repo_root)
        if "__pycache__" in relative.parts:
            if candidate.is_symlink() or (candidate.is_file() and candidate.suffix != ".pyc"):
                return None
            continue
        if candidate.is_symlink():
            return None
        if candidate.is_file():
            paths.add(relative.as_posix())
        elif not candidate.is_dir():
            return None
    return paths


def _expected_attempt_001_authority() -> dict[str, Any]:
    return {
        "amendment": {
            "binding": "sha256_at_consumption",
            "path": _AMENDMENT_001_PATH,
        },
        "attempt_id": "attempt_001",
        "authority_id": "iter000_001",
        "authorized_command": ["fieldtrue", "experiment", "iter000-amendment-001"],
        "consumption": {
            "creation_timing": "before_attempt_output_creation",
            "failure_mode": "fail_closed",
            "maximum_consumptions": 1,
            "proof_deletion_restores_authority": False,
            "receipt_path": _ITER000_ATTEMPT_001_RECEIPT_PATH,
            "receipt_presence_consumes_authority": True,
        },
        "iteration_id": _ITER000_ID,
        "protocol_hashes": None,
        "runtime_constraints": {"tls": _ITER000_TLS_CONSTRAINTS},
        "schema_version": "fieldtrue.attempt-authority.v1",
        "signer_anchor": {
            "binding": "sha256_at_consumption",
            "path": _ITER000_ANCHOR_PATH,
            "signer_public_key": _ITER000_SIGNER_PUBLIC_KEY,
        },
        "trust_model": {
            "blocks": [
                "ordinary_attempt_output_deletion",
                "concurrent_local_replay",
            ],
            "does_not_block": [
                "same_local_owner_deletes_receipt",
                "same_local_owner_rolls_back_repository",
                "signing_key_compromise",
            ],
            "external_timestamp": False,
            "signature": "git_pinned_local_ed25519",
        },
    }


def _verify_attempt_001_scientific_surface(
    repo_root: Path,
    *,
    git: str,
    head: str,
) -> tuple[bool, str]:
    authority_path = repo_root / _ITER000_ATTEMPT_001_AUTHORITY_PATH
    try:
        authority = _json(authority_path)
        authority_bytes = authority_path.read_bytes()
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return False, f"Attempt 001 authority is unreadable: {type(error).__name__}."
    if authority_path.is_symlink() or not authority_path.is_file():
        return False, "Attempt 001 authority must be a regular file."
    if canonical_json_pretty(authority) != authority_bytes:
        return False, "Attempt 001 authority must use canonical JSON."

    protocol_hashes = authority.get("protocol_hashes")
    normalized = dict(authority)
    normalized["protocol_hashes"] = None
    if normalized != _expected_attempt_001_authority() or not isinstance(protocol_hashes, dict):
        return False, "Attempt 001 authority core or single-use receipt policy differs."

    trigger_schema_paths = _git_tree_paths(
        repo_root, git, _ITER000_TRIGGER_COMMIT, "protocol/schemas"
    )
    if trigger_schema_paths is None or not trigger_schema_paths:
        return False, "Attempt 001 cannot resolve the triggering schema surface."
    expected_protocol_paths = _ITER000_ATTEMPT_001_PROTOCOL_PATHS | trigger_schema_paths
    if set(protocol_hashes) != expected_protocol_paths:
        return False, "Attempt 001 authority does not enumerate the exact protocol surface."
    for relative, expected_hash in protocol_hashes.items():
        if (
            not isinstance(relative, str)
            or not isinstance(expected_hash, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None
            or expected_hash == "0" * 64
        ):
            return False, f"Attempt 001 authority has an invalid hash binding: {relative}."
        path = repo_root / relative
        if path.is_symlink() or not path.is_file():
            return False, f"Attempt 001 protocol input is not a regular file: {relative}."
        if sha256_bytes(path.read_bytes()) != expected_hash:
            return False, f"Attempt 001 protocol hash mismatch: {relative}."
        if _git_blob_at_path(repo_root, git, head, relative) != path.read_bytes():
            return False, f"Attempt 001 protocol input is not committed at HEAD: {relative}."
    if (
        _git_blob_at_path(repo_root, git, head, _ITER000_ATTEMPT_001_AUTHORITY_PATH)
        != authority_bytes
    ):
        return False, "Attempt 001 authority is not committed at HEAD."

    try:
        anchor = load_signer_anchor(repo_root / _ITER000_ANCHOR_PATH)
    except (OSError, ValueError):
        return False, "Attempt 001 authority signer anchor is invalid."
    if anchor.signer_public_key != _ITER000_SIGNER_PUBLIC_KEY:
        return False, "Attempt 001 authority signer key differs from its frozen anchor."

    trigger_source_paths = _git_tree_paths(repo_root, git, _ITER000_TRIGGER_COMMIT, "src/fieldtrue")
    working_source_paths = _working_source_paths(repo_root)
    if trigger_source_paths is None or working_source_paths is None:
        return False, "Attempt 001 cannot resolve the complete source surface."
    if working_source_paths != trigger_source_paths:
        return False, "Attempt 001 added, removed, or linked a source-surface file."

    for relative in sorted(trigger_source_paths):
        path = repo_root / relative
        trigger_blob = _git_blob_at_path(repo_root, git, _ITER000_TRIGGER_COMMIT, relative)
        if trigger_blob is None:
            return False, f"Attempt 001 triggering source is unavailable: {relative}."
        current_bytes = path.read_bytes()
        if relative in _ITER000_ATTEMPT_001_AUTHORIZED_SOURCE_HASHES:
            before_hash, after_hash = _ITER000_ATTEMPT_001_AUTHORIZED_SOURCE_HASHES[relative]
            if (
                after_hash == "0" * 64
                or sha256_bytes(trigger_blob) != before_hash
                or sha256_bytes(current_bytes) != after_hash
                or protocol_hashes.get(relative) != after_hash
            ):
                return False, f"Attempt 001 authorized source binding differs: {relative}."
            continue
        if relative in _ITER000_ATTEMPT_001_RECOVERY_PATHS:
            if protocol_hashes.get(relative) != sha256_bytes(current_bytes):
                return False, f"Attempt 001 recovery control is not authority-bound: {relative}."
            continue
        if current_bytes != trigger_blob:
            return False, f"Attempt 001 changed an unauthorized source file: {relative}."

    gate_control_blob = _git_blob_at_path(
        repo_root, git, _ITER000_TRIGGER_COMMIT, _ITER000_GATE_CONTROL_PATH
    )
    try:
        trigger_gate_control = (
            json.loads(gate_control_blob) if gate_control_blob is not None else None
        )
        current_gate_control = _json(repo_root / _ITER000_GATE_CONTROL_PATH)
    except (OSError, ValueError, json.JSONDecodeError):
        return False, "Attempt 001 gate-control registry is unreadable."
    if not isinstance(trigger_gate_control, dict):
        return False, "Attempt 001 triggering gate-control registry is unavailable."
    trigger_gate_control.pop("execution_seal", None)
    current_gate_control.pop("execution_seal", None)
    if current_gate_control != trigger_gate_control:
        return False, "Attempt 001 changed the scientific gate-control contract."

    unchanged_protocol_paths = expected_protocol_paths - (
        _ITER000_ATTEMPT_001_RECOVERY_PATHS | set(_ITER000_ATTEMPT_001_AUTHORIZED_SOURCE_HASHES)
    )
    for relative in sorted(unchanged_protocol_paths):
        trigger_blob = _git_blob_at_path(repo_root, git, _ITER000_TRIGGER_COMMIT, relative)
        if trigger_blob != (repo_root / relative).read_bytes():
            return False, f"Attempt 001 changed a trigger-commit protocol input: {relative}."

    receipt_path = repo_root / _ITER000_ATTEMPT_001_RECEIPT_PATH
    receipt_directory = receipt_path.parent
    if receipt_directory.is_symlink() or (
        receipt_directory.exists() and not receipt_directory.is_dir()
    ):
        return False, "Attempt 001 authority consumption directory must not be linked."
    if receipt_path.is_symlink() or (receipt_path.exists() and not receipt_path.is_file()):
        return False, "Attempt 001 authority consumption path is not a regular file."
    return (
        True,
        "Attempt 001 authority binds the complete protocol and source surface; only the exact "
        "TLS and attempt-control changes are admitted.",
    )


def _verify_iteration_amendment_001(repo_root: Path) -> tuple[bool, str]:
    amendment_path = repo_root / _AMENDMENT_001_PATH
    try:
        amendment = _json(amendment_path)
        amendment_bytes = amendment_path.read_bytes()
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return False, f"Amendment 001 is unreadable: {type(error).__name__}."
    document_binding = amendment.get("amendment_document")
    document_sha256 = document_binding.get("sha256") if isinstance(document_binding, dict) else None
    if (
        not isinstance(document_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", document_sha256) is None
        or document_sha256 == "0" * 64
        or amendment != _expected_iteration_amendment_001(document_sha256)
    ):
        return False, "Amendment 001 differs from the exact authorized recovery contract."
    if canonical_json_pretty(amendment) != amendment_bytes:
        return False, "Amendment 001 must use canonical JSON."

    document_path = repo_root / _AMENDMENT_001_DOCUMENT_PATH
    ledger_path = repo_root / _ATTEMPT_000_LEDGER_PATH
    head_path = repo_root / _ATTEMPT_000_HEAD_PATH
    anchor_path = repo_root / _ITER000_ANCHOR_PATH
    frozen_paths = {relative: repo_root / relative for relative in _ITER000_FROZEN_HASHES}
    required_paths = {
        amendment_path,
        document_path,
        *frozen_paths.values(),
    }
    if any(path.is_symlink() or not path.is_file() for path in required_paths):
        return False, "Amendment 001 trust inputs must be regular files."
    if sha256_bytes(document_path.read_bytes()) != amendment["amendment_document"]["sha256"]:
        return False, "Amendment 001 document bytes do not match its contract."
    for relative, expected_hash in _ITER000_FROZEN_HASHES.items():
        if sha256_bytes(frozen_paths[relative].read_bytes()) != expected_hash:
            return False, f"Amendment 001 frozen bytes changed: {relative}."

    proof_root = repo_root / "experiments" / _ITER000_ID / "proof"
    attempt_root = repo_root / _ATTEMPT_000_PROOF_PATH
    if proof_root.is_symlink() or attempt_root.is_symlink():
        return False, "Iteration 000 proof roots must not be symbolic links."
    try:
        attempt_entries = {entry.name for entry in attempt_root.iterdir()}
        proof_children = tuple(proof_root.iterdir())
        proof_entries = {entry.name for entry in proof_children}
    except OSError:
        return False, "Attempt 000 proof evidence is unavailable."
    if attempt_entries != {"execution_ledger.jsonl", "execution_ledger.head.json"}:
        return False, "Attempt 000 must contain only its signed failure ledger and head."
    if not proof_entries.issubset({"attempt_000", "attempt_001"}) or any(
        child.is_symlink() or not child.is_dir() for child in proof_children
    ):
        return False, "Amendment 001 authorizes at most one isolated additional attempt root."

    try:
        anchor = load_signer_anchor(anchor_path)
        ledger_verification = verify_ledger(
            ledger_path,
            head_path,
            expected_signer_public_key=anchor.signer_public_key,
        )
        ledger_lines = ledger_path.read_text(encoding="utf-8").splitlines()
        events = [LedgerEvent.model_validate_json(line) for line in ledger_lines]
    except (OSError, ValueError, LedgerVerificationError) as error:
        return False, f"Attempt 000 ledger does not verify: {type(error).__name__}."
    if any(
        line.encode("utf-8") != canonical_json(event)
        for line, event in zip(ledger_lines, events, strict=True)
    ):
        return False, "Attempt 000 ledger must remain canonical JSONL."
    if (
        ledger_verification.event_count != 2
        or ledger_verification.head_hash != _ITER000_ATTEMPT_000_HEAD
        or [event.event_type for event in events] != ["run-started", "run-failed"]
        or any(event.run_id != _ITER000_ATTEMPT_000_RUN_ID for event in events)
        or any(event.runtime.git_commit != _ITER000_TRIGGER_COMMIT for event in events)
        or any(event.approval_receipt_hash is not None for event in events)
    ):
        return False, "Attempt 000 is not the exact pre-data failure authorized by Amendment 001."
    started, failed = events
    if (
        set(started.payload)
        != {
            "cloud_authorized",
            "gpu_authorized",
            "hypothesis",
            "live_action_authorized",
            "protocol_bundle",
        }
        or started.payload.get("cloud_authorized") is not False
        or started.payload.get("gpu_authorized") is not False
        or started.payload.get("live_action_authorized") is not False
        or started.payload.get("hypothesis") != _ITER000_HYPOTHESIS_PATH
        or failed.payload != {"error_type": "URLError", "message": _ITER000_ATTEMPT_000_FAILURE}
    ):
        return False, "Attempt 000 recorded data acceptance or a different failure cause."

    git = shutil.which("git")
    if git is None:
        return False, "Amendment 001 cannot verify committed evidence without Git."
    try:
        head = subprocess.run(  # noqa: S603 - fixed Git command
            [git, "rev-parse", "HEAD"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except subprocess.CalledProcessError:
        return False, "Amendment 001 cannot resolve HEAD."
    if (
        _GIT_OBJECT_ID_PATTERN.fullmatch(head) is None
        or not _git_commit_resolves(repo_root, git, _ITER000_TRIGGER_COMMIT)
        or not _git_is_ancestor(repo_root, git, _ITER000_TRIGGER_COMMIT, head)
    ):
        return False, "Amendment 001 triggering commit is not an ancestor of HEAD."
    surface_valid, surface_detail = _verify_attempt_001_scientific_surface(
        repo_root,
        git=git,
        head=head,
    )
    if not surface_valid:
        return False, surface_detail
    trust_inputs = (
        _AMENDMENT_001_PATH,
        _AMENDMENT_001_DOCUMENT_PATH,
        _ITER000_ATTEMPT_001_AUTHORITY_PATH,
        _ATTEMPT_000_LEDGER_PATH,
        _ATTEMPT_000_HEAD_PATH,
        _ITER000_ANCHOR_PATH,
        _ITER000_DATASET_PATH,
        _ITER000_HYPOTHESIS_PATH,
        "pyproject.toml",
        "uv.lock",
        "src/fieldtrue/adapters/adapt.py",
        "src/fieldtrue/cli.py",
        "src/fieldtrue/experiment.py",
        "src/fieldtrue/mission.py",
        "src/fieldtrue/verification.py",
    )
    for relative in trust_inputs:
        path = repo_root / relative
        if path.is_symlink() or not path.is_file():
            return False, f"Amendment 001 trust input is missing: {relative}."
        if _git_blob_at_path(repo_root, git, head, relative) != path.read_bytes():
            return False, f"Amendment 001 trust input is not committed at HEAD: {relative}."
    for relative in (_ITER000_ANCHOR_PATH, _ITER000_DATASET_PATH, _ITER000_HYPOTHESIS_PATH):
        if (
            _git_blob_at_path(repo_root, git, _ITER000_TRIGGER_COMMIT, relative)
            != (repo_root / relative).read_bytes()
        ):
            return False, f"Amendment 001 changed a trigger-commit input: {relative}."
    if (repo_root / _ITER000_HYPOTHESIS_PATH).read_bytes() != _root_preregistration_bytes(
        repo_root, _ITER000_HYPOTHESIS_PATH
    ):
        return False, "Amendment 001 changed the root-preregistered hypothesis."

    if not _certifi_dependency_is_locked(repo_root):
        return False, "Amendment 001 requires a locked direct certifi dependency."
    if not _adapt_tls_source_is_verified(repo_root / "src" / "fieldtrue" / "adapters" / "adapt.py"):
        return False, "Amendment 001 TLS source contract is missing or permits a bypass."
    if not _verified_tls_runtime_active():
        return False, "Amendment 001 TLS runtime is not certifi-backed and fully verified."
    return (
        True,
        "Amendment 001 authorizes one isolated certifi-backed retry from signed "
        "pre-data failure evidence.",
    )


def _verify_publication_transition(
    repo_root: Path,
    loop: dict[str, Any],
    required_requirements: set[str],
) -> tuple[bool, str]:
    transition = loop.get("publication_transition")
    if not isinstance(transition, dict) or set(transition) != {
        "status",
        "receipt_path",
        "signer_anchor_path",
        "block_reason",
    }:
        return False, "Publication transition state is missing or malformed."
    stages = loop.get("stages")
    current_stage = loop.get("current_stage")
    if (
        not isinstance(stages, list)
        or not all(isinstance(stage, str) for stage in stages)
        or not isinstance(current_stage, str)
        or current_stage not in stages
        or "published" not in stages
    ):
        return False, "Publication transition cannot resolve the mission stage."
    publication_reached = current_stage in {"published", "learned"}
    status = transition.get("status")
    if status == "blocked":
        valid_block = (
            transition.get("receipt_path") is None
            and transition.get("signer_anchor_path") is None
            and isinstance(transition.get("block_reason"), str)
            and bool(transition["block_reason"].strip())
        )
        if not valid_block:
            return False, "Blocked publication state must carry a reason and no receipt paths."
        if publication_reached:
            return False, "Published or learned stage requires an authorized publication receipt."
        return True, "Publication remains explicitly blocked pending signed, anchored evidence."
    if status != "authorized" or transition.get("block_reason") is not None:
        return False, "Publication transition status must be blocked or authorized."

    receipt_relative = _safe_relative_path(transition.get("receipt_path"))
    anchor_relative = _safe_relative_path(transition.get("signer_anchor_path"))
    if receipt_relative is None or anchor_relative is None:
        return False, "Publication receipt and signer anchor must be safe repository paths."
    receipt_path = repo_root / receipt_relative
    anchor_path = repo_root / anchor_relative
    if receipt_path.is_symlink() or anchor_path.is_symlink():
        return False, "Publication receipt and signer anchor must be regular files."
    try:
        receipt = _json(receipt_path)
        receipt_bytes = receipt_path.read_bytes()
        anchor = load_signer_anchor(anchor_path)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return False, f"Publication evidence is unreadable: {type(error).__name__}."
    if canonical_json_pretty(receipt) != receipt_bytes:
        return False, "Publication receipt must use canonical JSON."
    if (
        anchor.anchor_id != _PUBLICATION_ANCHOR_ID
        or anchor.ledger_scope != _PUBLICATION_LEDGER_SCOPE
    ):
        return False, "Publication signer anchor has the wrong identity or scope."
    expected_receipt_keys = {
        "schema_version",
        "mission_id",
        "target_stage",
        "requirements",
        "evidence",
        "signer_public_key",
        "receipt_hash",
        "signature",
    }
    if set(receipt) != expected_receipt_keys:
        return False, "Publication receipt fields are not exact."
    requirements = receipt.get("requirements")
    evidence = receipt.get("evidence")
    if (
        receipt.get("schema_version") != "fieldtrue.publication-gate-receipt.v1"
        or receipt.get("mission_id") != "fieldtrue"
        or receipt.get("target_stage") != "published"
        or not isinstance(requirements, list)
        or not all(isinstance(requirement, str) for requirement in requirements)
        or len(requirements) != len(set(requirements))
        or set(requirements) != required_requirements
        or not isinstance(evidence, dict)
        or set(evidence) != required_requirements
        or receipt.get("signer_public_key") != anchor.signer_public_key
    ):
        return False, "Publication receipt does not cover the exact required gate set."
    receipt_hash = receipt.get("receipt_hash")
    signature = receipt.get("signature")
    if (
        not isinstance(receipt_hash, str)
        or re.fullmatch(r"[0-9a-f]{64}", receipt_hash) is None
        or not isinstance(signature, str)
        or re.fullmatch(r"[0-9a-f]{128}", signature) is None
    ):
        return False, "Publication receipt hash or signature is malformed."
    receipt_body = dict(receipt)
    receipt_body.pop("receipt_hash")
    receipt_body.pop("signature")
    if sha256_value(receipt_body) != receipt_hash:
        return False, "Publication receipt content hash does not match."
    try:
        VerifyKey(bytes.fromhex(anchor.signer_public_key)).verify(
            bytes.fromhex(receipt_hash), bytes.fromhex(signature)
        )
    except (BadSignatureError, ValueError):
        return False, "Publication receipt signature does not match the pinned signer."

    git = shutil.which("git")
    if git is None:
        return False, "Publication evidence cannot verify because Git is unavailable."
    try:
        head = subprocess.run(  # noqa: S603 - fixed Git command
            [git, "rev-parse", "HEAD"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except subprocess.CalledProcessError:
        return False, "Publication evidence cannot resolve HEAD."
    if _GIT_OBJECT_ID_PATTERN.fullmatch(head) is None:
        return False, "Publication evidence resolved an invalid HEAD."
    for relative, expected_bytes in (
        ("mission/loop.json", canonical_json_pretty(loop)),
        (receipt_relative, receipt_bytes),
        (anchor_relative, anchor_path.read_bytes()),
    ):
        if _git_blob_at_path(repo_root, git, head, relative) != expected_bytes:
            return False, f"Publication trust input is not anchored at HEAD: {relative}."

    evidence_paths: set[str] = set()
    for requirement in requirements:
        item = evidence.get(requirement)
        if not isinstance(item, dict) or set(item) != {"path", "git_commit", "sha256"}:
            return False, f"Publication evidence is malformed for {requirement}."
        evidence_relative = _safe_relative_path(item.get("path"))
        commit = item.get("git_commit")
        digest = item.get("sha256")
        if (
            evidence_relative is None
            or evidence_relative in evidence_paths
            or evidence_relative in {receipt_relative, anchor_relative, "mission/loop.json"}
            or not isinstance(commit, str)
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or not _git_commit_resolves(repo_root, git, commit)
            or not _git_is_ancestor(repo_root, git, commit, head)
        ):
            return False, f"Publication evidence anchor is invalid for {requirement}."
        blob = _git_blob_at_path(repo_root, git, commit, evidence_relative)
        if blob is None or sha256_bytes(blob) != digest:
            return False, f"Publication evidence bytes do not verify for {requirement}."
        evidence_paths.add(evidence_relative)
    return True, "Publication authorization is signed and every gate has distinct Git evidence."


def validate_mission(repo_root: Path) -> MissionValidation:
    checks: list[ValidationCheck] = []
    contract = _json(repo_root / "mission" / "contract.json")
    loop = _json(repo_root / "mission" / "loop.json")
    authorities = set(contract.get("execution_authorities", []))
    forbidden = set(contract.get("forbidden_authorities", []))
    checks.append(
        _check(
            "owner-boundary",
            contract.get("owner") == "Daniel Wahnich",
            "Mission owner must remain Daniel Wahnich.",
        )
    )
    checks.append(
        _check(
            "execution-authority",
            authorities == {"replay", "simulator", "testbed"}
            and "flight" not in authorities
            and "flight" in forbidden,
            "v0 permits replay/simulator/testbed and explicitly forbids flight.",
        )
    )
    stages = loop.get("stages", [])
    checks.append(
        _check(
            "mission-stage",
            loop.get("current_stage") in stages and len(stages) == len(set(stages)),
            "Current stage must be a unique registered lifecycle stage.",
        )
    )
    checks.append(
        _check(
            "research-engine-deferred",
            contract.get("research_engine_policy")
            == "deferred_to_separate_repository_after_multiple_complete_cycles",
            "The standalone research engine remains deferred and separate.",
        )
    )
    transition_requirements = loop.get("transition_requirements")
    raw_publication_requirements = (
        transition_requirements.get("published")
        if isinstance(transition_requirements, dict)
        else None
    )
    publication_requirements = (
        set(raw_publication_requirements)
        if isinstance(raw_publication_requirements, list)
        and all(isinstance(item, str) for item in raw_publication_requirements)
        else set()
    )
    required_publication_gates = {
        "claim_registry_updated",
        "independent_verification",
        "gate_sensitivity_verified",
        "independent_replication_or_declared_limitation",
        "external_domain_review",
        "venue_scope_review",
        "manuscript_artifact_traceability",
        "adversarial_review",
        "author_tool_disclosure",
        "license_and_rights_review",
        "conventional_journal_target_recorded",
        "handoff_refreshed",
    }
    checks.append(
        _check(
            "publication-gates",
            required_publication_gates == publication_requirements,
            "Publication requires scientific, external-review, venue, rights, and artifact gates.",
        )
    )
    publication_transition_valid, publication_transition_detail = _verify_publication_transition(
        repo_root, loop, required_publication_gates
    )
    checks.append(
        _check(
            "publication-transition-evidence",
            publication_transition_valid,
            publication_transition_detail,
        )
    )
    checks.append(
        _check(
            "gate-falsification",
            _gate_controls_valid(loop),
            "Every claim-bearing gate requires preregistered positive, negative, and "
            "executable sensitivity controls.",
        )
    )
    gate_registry_valid, gate_registry_detail = _verify_gate_control_registry(
        repo_root, repo_root / "protocol" / "gate_controls" / "v1.json"
    )
    checks.append(
        _check(
            "gate-control-registry",
            gate_registry_valid,
            gate_registry_detail,
        )
    )
    root_files = _first_commit_files(repo_root)
    checks.append(
        _check(
            "preregistration-first",
            root_files == ["experiments/iter000_nasa_adapt_corpus_readiness/HYPOTHESIS.md"],
            "The root commit must contain only the iteration-000 hypothesis.",
        )
    )
    hypothesis = repo_root / "experiments" / "iter000_nasa_adapt_corpus_readiness" / "HYPOTHESIS.md"
    hypothesis_text = hypothesis.read_text(encoding="utf-8")
    hypothesis_relative = "experiments/iter000_nasa_adapt_corpus_readiness/HYPOTHESIS.md"
    checks.append(
        _check(
            "hypothesis-status",
            "Status: **PRE-REGISTERED**" in hypothesis_text
            and "Prior exposure disclosure" in hypothesis_text
            and hypothesis.read_bytes()
            == _root_preregistration_bytes(repo_root, hypothesis_relative),
            "Iteration 000 must byte-match its root-commit preregistration.",
        )
    )
    dataset_lock = load_adapt_lock(repo_root / "protocol" / "datasets" / "nasa_adapt_v1.json")
    checks.append(
        _check(
            "dataset-lock",
            dataset_lock.expected_experiment_files == 16
            and all(resource.url.startswith("https://") for resource in dataset_lock.resources),
            "NASA ADAPT bytes and exact expected file count are frozen.",
        )
    )
    amendment_valid, amendment_detail = _verify_iteration_amendment_001(repo_root)
    checks.append(
        _check(
            "iteration-amendment-001",
            amendment_valid,
            amendment_detail,
        )
    )
    claims = _claims(repo_root / "claims" / "registry.jsonl")
    claim_ids = [claim.claim_id for claim in claims]
    checks.append(
        _check(
            "claim-registry",
            bool(claims) and len(claim_ids) == len(set(claim_ids)),
            "Claim registry must be nonempty, typed, and unique.",
        )
    )
    memory_path = repo_root / "memory" / "research_engine_extraction.jsonl"
    memory_count, _ = verify_memory(memory_path)
    checks.append(
        _check(
            "research-memory",
            memory_path.is_file() and memory_count > 0,
            f"Research-engine extraction memory verifies ({memory_count} events).",
        )
    )
    memory_git_anchors_valid, memory_git_anchors_detail = _verify_memory_git_anchors(
        repo_root, memory_path
    )
    checks.append(
        _check(
            "research-memory-git-anchors",
            memory_git_anchors_valid,
            memory_git_anchors_detail,
        )
    )
    try:
        signer_anchor = load_signer_anchor(
            repo_root / "protocol" / "trust" / "iter000_signer_anchor.json"
        )
        signer_anchor_valid = (
            signer_anchor.anchor_id == "iter000-execution-ledger"
            and signer_anchor.ledger_scope == "iter000_nasa_adapt_corpus_readiness"
        )
    except (OSError, ValueError):
        signer_anchor_valid = False
    checks.append(
        _check(
            "signer-anchor",
            signer_anchor_valid,
            "Iteration 000 must use the Git-pinned execution-ledger signer.",
        )
    )
    schema_errors = verify_schemas(repo_root)
    checks.append(
        _check(
            "schemas",
            not schema_errors,
            "Committed schemas match Pydantic contracts. " + "; ".join(schema_errors),
        )
    )
    checks.append(
        _check(
            "lockfile",
            (repo_root / "uv.lock").is_file(),
            "A committed uv.lock is required before execution.",
        )
    )
    source_text = "\n".join(
        path.read_text(encoding="utf-8") for path in (repo_root / "src").rglob("*.py")
    )
    forbidden_import = re.search(
        r"(?m)^\s*(?:from|import)\s+(?:aweb|google\.cloud|boto3|vertexai)(?:\.|\s|$)",
        source_text,
    )
    checks.append(
        _check(
            "provider-independence",
            forbidden_import is None
            and not (repo_root / "src" / "fieldtrue" / "adapters" / "aweb.py").exists(),
            "Core has no Aweb/cloud SDK import or placeholder Aweb adapter.",
        )
    )
    return MissionValidation(
        passed=all(check.passed for check in checks),
        checks=tuple(checks),
    )
