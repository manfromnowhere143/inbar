"""Repository-level mission invariant validator."""

from __future__ import annotations

import ast
import json
import os
import platform  # noqa: F401 - retained for historical test monkeypatches
import re
import shutil  # noqa: F401 - retained for historical test monkeypatches
import ssl
import stat
import subprocess
import tomllib
import urllib.request  # noqa: F401 - retained for historical test monkeypatches
import xml.etree.ElementTree as ET
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as distribution_version
from itertools import pairwise
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import Any
from urllib.parse import urlsplit

import certifi
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from packaging.tags import platform_tags
from pydantic import BaseModel, ConfigDict

import fieldtrue.runner_trust as runner_trust
from fieldtrue.acquisition import (
    AcquisitionAuditError,
    load_acquisition_contract,
    verify_preregistration_binding,
)
from fieldtrue.adapters import adapt as adapt_adapter
from fieldtrue.adapters.adapt import load_adapt_lock
from fieldtrue.canonical import canonical_json, canonical_json_pretty, sha256_bytes, sha256_value
from fieldtrue.domain import ClaimRecord
from fieldtrue.git_trust import (
    TRUSTED_GIT_PATH,
    GitTrustError,
    git_environment,
    trusted_repository_git,
)
from fieldtrue.memory import load_memory_records, verify_memory
from fieldtrue.receipts import (
    LedgerEvent,
    LedgerVerificationError,
    PublicationSignerAnchor,
    SignerAnchor,
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
_MAX_PUBLICATION_TRUST_INPUT_BYTES = 16 * 1024 * 1024
_ITER000_ID = "iter000_nasa_adapt_corpus_readiness"
_ITER001_ACQUISITION_CONTRACT_PATH = "protocol/acquisition/iter001_contract.json"
_AMENDMENT_001_PATH = "protocol/amendments/iter000_001.json"
_AMENDMENT_001_DOCUMENT_PATH = f"experiments/{_ITER000_ID}/AMENDMENT_001.md"
_ATTEMPT_000_PROOF_PATH = f"experiments/{_ITER000_ID}/proof/attempt_000"
_ATTEMPT_000_LEDGER_PATH = f"{_ATTEMPT_000_PROOF_PATH}/execution_ledger.jsonl"
_ATTEMPT_000_HEAD_PATH = f"{_ATTEMPT_000_PROOF_PATH}/execution_ledger.head.json"
_ITER000_ANCHOR_PATH = "protocol/trust/iter000_signer_anchor.json"
_ITER000_DATASET_PATH = "protocol/datasets/nasa_adapt_v1.json"
_ITER000_GATE_CONTROL_PATH = "protocol/gate_controls/v1.json"
_ITER000_GATE_CONTROL_COMMIT = "d07789886f7350a0405f49a358e3dabfdca6c878"
_TRUSTED_GIT_PATH = TRUSTED_GIT_PATH
_GIT_TIMEOUT_SECONDS = 10
_GATE_CONTROL_REPORT = ".inbar-gate-controls.xml"
_GATE_CONTROL_ROOT_DISTRIBUTIONS = frozenset({"certifi", "networkx", "pydantic", "pytest"})
_ITER000_HYPOTHESIS_PATH = f"experiments/{_ITER000_ID}/HYPOTHESIS.md"
_ITER000_ATTEMPT_001_AUTHORITY_PATH = "protocol/attempt_authorities/iter000_001.json"
_ITER000_ATTEMPT_001_RECEIPT_PATH = (
    f"experiments/{_ITER000_ID}/authority/attempt_001_consumption.json"
)
_ITER000_ATTEMPT_001_PROOF_PATH = f"experiments/{_ITER000_ID}/proof/attempt_001"
_ITER000_TRIGGER_COMMIT = "2fb078a1cac5f76f251ab49e0368ae0ea3e8da2e"
_ITER000_ATTEMPT_001_EXECUTION_COMMIT = "ab20d41be48003c443a807c733c4c8ce43445e01"
_ITER000_ATTEMPT_001_EXECUTION_TREE = "e3d8a8609e483b37c755b252e4f43b57b4731480"
_ITER000_ATTEMPT_001_EXECUTION_SOURCE_TREE = "48a5e6a2c0af64baacfe5928d66eaa227439b11a"
_ITER000_PROOF_COMMIT = "15cd75dd761a1c3f1d75994445a9ce702c58810a"
_ITER000_PROOF_COMMIT_TREE = "388a78ef4afe4187dc0d2389feb28899571589fb"
_ITER000_ATTEMPT_001_PROOF_TREE = "5ad82ba61c522fc3e292ab7ceed9f7085b556673"
_ITER000_VERIFICATION_CONTRACT_COMMIT = "f9983e26e0e9d48c14016dfc4d897962767f8da8"
_ITER000_VERIFICATION_CONTRACT_TREE = "552755b74e49ab7810df2e965519f556796ba604"
_ITER000_VERIFICATION_CORRECTION_COMMIT = "10925e603f4dc24e1e3f990266c80300cc60ca3b"
_ITER000_VERIFICATION_CORRECTION_TREE = "30d19a093c1704144f4dc1e43f5009d26313cdf8"
_ITER000_VERIFICATION_CONTRACT_PATH = "protocol/amendments/iter000_verification_001.json"
_ITER000_VERIFICATION_CONTRACT_SHA256 = (
    "919df0feab263c52889964b728ddd296c8d585019a66fe3c01bd997fc893bfa9"
)
_ITER000_VERIFICATION_CORRECTION_PATH = "protocol/amendments/iter000_verification_002.json"
_ITER000_VERIFICATION_CORRECTION_SHA256 = (
    "45d5d90c63bfda2b84bf962c9d7bf4c76db58fb241b7eb6d1b146a5535c7382c"
)
_ITER000_ATTEMPT_001_AUTHORITY_SHA256 = (
    "ef480a24ebe7912523ba64642127971e56d96e66689d2c7f9cea39f3413bc99a"
)
_ITER000_ATTEMPT_001_CONSUMPTION_SHA256 = (
    "8d155b56440a4dfa25cbdfa400344a32b29e8d877cd39fa4f2c0612b4371b8aa"
)
_ITER000_ATTEMPT_001_LEDGER_SHA256 = (
    "cb4aaf5d1cdabc42db25883d9e0db448cd41df56dcc8ebfd12eb73143151b728"
)
_ITER000_ATTEMPT_001_HEAD_SHA256 = (
    "d89901abec03c460bdcdaa2985dc65d6d9a3b076c16100f56c1f3a4f1dc0665e"
)
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


def _materialize_gate_control_snapshot(
    repo_root: Path,
    *,
    git: str,
    destination: Path,
) -> bool:
    paths = {"pyproject.toml", "tests/__init__.py", "tests/unit/__init__.py", "uv.lock"}
    for prefix in ("src/fieldtrue", "tests"):
        discovered = _git_tree_paths(repo_root, git, _ITER000_GATE_CONTROL_COMMIT, prefix)
        if discovered is None:
            return False
        paths.update(discovered)
    for relative in sorted(paths):
        data = _git_blob_at_path(
            repo_root,
            git,
            _ITER000_GATE_CONTROL_COMMIT,
            relative,
        )
        if data is None:
            return False
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return True


_GateControlRunner = runner_trust.AuthenticatedRunner
_LockedWheel = runner_trust.LockedWheel


def _authenticated_artifact_bytes(
    *,
    url: str,
    expected_sha256: str,
    expected_size: int,
    cache_root: Path,
    cache_namespace: str,
) -> bytes | None:
    try:
        return runner_trust.authenticated_artifact_bytes(
            url=url,
            expected_sha256=expected_sha256,
            expected_size=expected_size,
            cache_root=cache_root,
            cache_namespace=cache_namespace,
        )
    except runner_trust.RunnerTrustError:
        return None


def _locked_gate_control_packages(
    lock: dict[str, object],
) -> dict[str, dict[str, object]] | None:
    try:
        return runner_trust.resolve_locked_packages(
            lock,
            _GATE_CONTROL_ROOT_DISTRIBUTIONS,
        )
    except runner_trust.RunnerTrustError:
        return None


def _locked_gate_control_wheels(
    lock: dict[str, object],
) -> tuple[_LockedWheel, ...] | None:
    try:
        return runner_trust.resolve_locked_wheels(
            lock,
            root_distributions=_GATE_CONTROL_ROOT_DISTRIBUTIONS,
            target_platform_tags=tuple(platform_tags()),
        )
    except runner_trust.RunnerTrustError:
        return None


def _extract_authenticated_wheels(
    artifacts: tuple[tuple[_LockedWheel, bytes], ...],
    site_packages: Path,
) -> bool:
    try:
        runner_trust.extract_authenticated_wheels(artifacts, site_packages)
    except runner_trust.RunnerTrustError:
        return False
    return True


def _prepare_gate_control_runner(snapshot_root: Path) -> _GateControlRunner | None:
    try:
        return runner_trust.prepare_authenticated_runner(
            snapshot_root,
            snapshot_root,
            root_distributions=_GATE_CONTROL_ROOT_DISTRIBUTIONS,
            required_imports=("pytest",),
            mutable_output_paths=(snapshot_root / _GATE_CONTROL_REPORT,),
        )
    except runner_trust.RunnerTrustError:
        return None


def _gate_control_runner_is_unchanged(
    snapshot_root: Path,
    runner: _GateControlRunner,
) -> bool:
    try:
        snapshot_matches = snapshot_root.resolve(strict=True) == runner.snapshot_root.resolve(
            strict=True
        )
    except OSError:
        return False
    return snapshot_matches and runner_trust.runner_is_unchanged(runner)


def _run_gate_control_nodes(
    snapshot_root: Path,
    node_ids: list[str],
    runner: _GateControlRunner,
) -> subprocess.CompletedProcess[str]:
    if not _gate_control_runner_is_unchanged(snapshot_root, runner):
        raise OSError("gate-control runner changed before child execution")
    if not runner_trust.ensure_private_directory(runner.scratch_root):
        raise OSError("gate-control scratch directory is not private")
    environment = {
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PATH": "/usr/bin:/bin",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "TEMP": str(runner.scratch_root),
        "TMP": str(runner.scratch_root),
        "TMPDIR": str(runner.scratch_root),
        "TZ": "UTC",
    }
    report_path = snapshot_root / _GATE_CONTROL_REPORT
    if report_path.exists() or report_path.is_symlink():
        raise OSError("gate-control report path already exists")
    return subprocess.run(  # noqa: S603 - node IDs and paths are validated before execution
        [
            str(runner.python_path),
            "-I",
            "-B",
            "-S",
            "-c",
            "import sys;sys.path[:0]=sys.argv[1:3];import pytest;"
            "raise SystemExit(pytest.main(sys.argv[3:]))",
            str(snapshot_root / "src"),
            str(runner.site_packages),
            "-q",
            "--strict-config",
            "--strict-markers",
            "-p",
            "no:cacheprovider",
            "-o",
            "addopts=",
            "--junitxml",
            str(report_path),
            *node_ids,
        ],
        cwd=snapshot_root,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
        env=environment,
    )


def _gate_control_report_is_exact(snapshot_root: Path, node_ids: list[str]) -> bool:
    report_path = snapshot_root / _GATE_CONTROL_REPORT
    data = runner_trust.stable_regular_bytes(report_path, maximum_bytes=1024 * 1024)
    if data is None:
        return False
    try:
        document = ET.fromstring(  # noqa: S314 - bounded output from pinned isolated pytest
            data
        )
    except ET.ParseError:
        return False
    cases = document.findall(".//testcase")
    expected_names = [node_id.rsplit("::", 1)[1] for node_id in node_ids]
    observed_names = [case.attrib.get("name") for case in cases]
    if observed_names != expected_names:
        return False
    return all(
        not any(case.find(tag) is not None for tag in ("error", "failure", "skipped"))
        for case in cases
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
    try:
        git = _trusted_git(repo_root)
    except ValueError as error:
        return False, f"Gate control Git trust failed: {error}."
    try:
        if not _git_commit_resolves(repo_root, git, _ITER000_GATE_CONTROL_COMMIT):
            return False, "Gate control historical implementation commit is unavailable."
        historical_registry = _git_blob_at_path(
            repo_root,
            git,
            _ITER000_GATE_CONTROL_COMMIT,
            _ITER000_GATE_CONTROL_PATH,
        )
        if historical_registry is None:
            return False, "Gate control historical registry is unavailable."
        with TemporaryDirectory(prefix="fieldtrue-iter000-controls-") as temporary:
            snapshot_root = Path(temporary)
            if not _materialize_gate_control_snapshot(
                repo_root,
                git=git,
                destination=snapshot_root,
            ):
                return False, "Gate control historical implementation cannot be materialized."
            runner = _prepare_gate_control_runner(snapshot_root)
            if runner is None:
                return False, "Gate control runner does not match the frozen historical lock."
            failures: list[str] = []
            node_ids: list[str] = []
            for gate_id, failure_class in _ITER000_GATE_FAILURE_CLASSES.items():
                control = by_gate[gate_id]
                if control.get("failure_class") != failure_class:
                    failures.append(f"{gate_id}: failure class")
                for role in ("positive_control", "negative_control"):
                    node_id = control.get(role)
                    if not _control_node_is_substantive(
                        snapshot_root,
                        node_id,
                        gate_id=gate_id,
                        role=role.removesuffix("_control"),
                        expected_status=("pass" if role == "positive_control" else failure_class),
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
            control_set_hash = _gate_control_set_hash(
                snapshot_root,
                iteration_id=registry["iteration_id"],
                controls=controls,
                sealed_paths=tuple(sealed_paths),
            )
            if (
                control_set_hash is None
                or execution_seal.get("control_set_sha256") != control_set_hash
            ):
                return False, "Gate control source seal does not match the executable control set."
            registry_bytes = runner_trust.stable_regular_bytes(
                path,
                maximum_bytes=2 * 1024 * 1024,
            )
            if registry_bytes != historical_registry:
                return False, "Gate control registry differs from its historical Git binding."
            execution = _run_gate_control_nodes(snapshot_root, node_ids, runner)
            exact_execution = _gate_control_report_is_exact(snapshot_root, node_ids)
            if not _gate_control_runner_is_unchanged(snapshot_root, runner):
                return False, "Gate control runner identity changed during historical execution."
            if (
                _gate_control_set_hash(
                    snapshot_root,
                    iteration_id=registry["iteration_id"],
                    controls=controls,
                    sealed_paths=tuple(sealed_paths),
                )
                != control_set_hash
                or runner_trust.stable_regular_bytes(
                    path,
                    maximum_bytes=2 * 1024 * 1024,
                )
                != registry_bytes
            ):
                return False, "Gate control source or registry changed during execution."
    except (OSError, subprocess.SubprocessError) as error:
        return False, f"Gate control execution failed to run: {type(error).__name__}."
    result = {
        "schema_version": "fieldtrue.gate-control-execution-result.v1",
        "control_set_sha256": control_set_hash,
        "executed_nodes": node_ids,
        "exit_code": execution.returncode,
        "outcome": "passed" if execution.returncode == 0 and exact_execution else "failed",
    }
    result_hash = sha256_value(result)
    if (
        execution.returncode != 0
        or not exact_execution
        or execution_seal.get("passing_result_sha256") != result_hash
    ):
        output = (execution.stdout + execution.stderr).strip()[-500:]
        return False, f"Gate controls did not reproduce their sealed passing result: {output}"
    return (
        True,
        f"Executed and verified {len(node_ids)} distinct controls against the sealed result.",
    )


def _git_environment() -> dict[str, str]:
    return git_environment()


def _trusted_git(repo_root: Path) -> str:
    return trusted_repository_git(repo_root, _TRUSTED_GIT_PATH)


def _root_commit(repo_root: Path) -> str:
    git = _trusted_git(repo_root)
    root_commit = subprocess.run(  # noqa: S603 - fixed executable and literal arguments
        [git, "rev-list", "--max-parents=0", "HEAD"],
        cwd=repo_root,
        check=True,
        capture_output=True,
        env=_git_environment(),
        timeout=_GIT_TIMEOUT_SECONDS,
        text=True,
    ).stdout.strip()
    if re.fullmatch(r"[0-9a-f]{40}", root_commit) is None:
        raise ValueError("git returned an invalid root commit")
    return root_commit


def _first_commit_files(repo_root: Path) -> list[str]:
    git = _trusted_git(repo_root)
    root_commit = _root_commit(repo_root)
    output = subprocess.run(  # noqa: S603 - root_commit is validated hexadecimal Git output
        [git, "show", "--pretty=", "--name-only", root_commit],
        cwd=repo_root,
        check=True,
        capture_output=True,
        env=_git_environment(),
        timeout=_GIT_TIMEOUT_SECONDS,
        text=True,
    ).stdout
    return sorted(line for line in output.splitlines() if line)


def _root_preregistration_bytes(repo_root: Path, relative_path: str) -> bytes:
    git = _trusted_git(repo_root)
    return subprocess.run(  # noqa: S603 - fixed Git command and validated root commit
        [git, "show", f"{_root_commit(repo_root)}:{relative_path}"],
        cwd=repo_root,
        check=True,
        capture_output=True,
        env=_git_environment(),
        timeout=_GIT_TIMEOUT_SECONDS,
    ).stdout


def _git_commit_resolves(repo_root: Path, git: str, object_id: str) -> bool:
    if _GIT_OBJECT_ID_PATTERN.fullmatch(object_id) is None:
        return False
    result = subprocess.run(  # noqa: S603 - Git path and object ID are validated
        [git, "cat-file", "-e", f"{object_id}^{{commit}}"],
        cwd=repo_root,
        check=False,
        env=_git_environment(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=_GIT_TIMEOUT_SECONDS,
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
        env=_git_environment(),
        timeout=_GIT_TIMEOUT_SECONDS,
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
        env=_git_environment(),
        timeout=_GIT_TIMEOUT_SECONDS,
    )
    return blob_result.stdout if blob_result.returncode == 0 else None


def _verify_memory_git_anchors(repo_root: Path, memory_path: Path) -> tuple[bool, str]:
    try:
        git = _trusted_git(repo_root)
        head = subprocess.run(  # noqa: S603 - fixed trusted Git identity query
            [git, "rev-parse", "--verify", "HEAD^{commit}"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            env=_git_environment(),
            timeout=_GIT_TIMEOUT_SECONDS,
            text=True,
        ).stdout.strip()
    except ValueError as error:
        return False, f"Research memory Git trust failed: {error}."
    except (OSError, subprocess.SubprocessError):
        return False, "Research memory Git HEAD cannot be captured."
    if _GIT_OBJECT_ID_PATTERN.fullmatch(head) is None:
        return False, "Research memory Git HEAD has an invalid object identity."
    records = load_memory_records(memory_path)
    failures: list[str] = []
    commit_results: dict[str, bool] = {}

    def commit_is_recoverable(object_id: str) -> bool:
        if object_id not in commit_results:
            commit_results[object_id] = _git_commit_resolves(
                repo_root, git, object_id
            ) and _git_is_ancestor(repo_root, git, object_id, head)
        return commit_results[object_id]

    for record in records:
        if not commit_is_recoverable(record.source_commit):
            failures.append(
                f"{record.event_id}: source_commit is not a Git commit reachable from HEAD"
            )
        for index, evidence in enumerate(record.evidence):
            if urlsplit(evidence.uri).scheme:
                continue
            evidence_label = f"{record.event_id}: evidence[{index}] {evidence.uri}"
            if evidence.git_commit is None or not commit_is_recoverable(evidence.git_commit):
                failures.append(
                    f"{evidence_label}: git_commit is not a Git commit reachable from HEAD"
                )
                continue
            blob = _git_blob_at_path(repo_root, git, evidence.git_commit, evidence.uri)
            if blob is None:
                failures.append(f"{evidence_label}: path is not a historical Git blob")
                continue
            if evidence.sha256 is not None and sha256_bytes(blob) != evidence.sha256:
                failures.append(f"{evidence_label}: sha256 does not match the historical Git blob")

    try:
        _trusted_git(repo_root)
        final_head = subprocess.run(  # noqa: S603 - fixed trusted Git identity query
            [git, "rev-parse", "--verify", "HEAD^{commit}"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            env=_git_environment(),
            timeout=_GIT_TIMEOUT_SECONDS,
            text=True,
        ).stdout.strip()
    except (GitTrustError, OSError, subprocess.SubprocessError, ValueError):
        return False, "Research memory Git trust changed during verification."
    if final_head != head:
        return False, "Research memory Git HEAD changed during verification."
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


def _read_repo_regular_file(repo_root: Path, relative_path: str) -> bytes:
    safe_path = _safe_relative_path(relative_path)
    if safe_path is None:
        raise ValueError("repository file path is unsafe")
    parts = PurePosixPath(safe_path).parts
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | no_follow
    descriptors: list[int] = []
    try:
        current = os.open(repo_root, directory_flags)
        descriptors.append(current)
        for component in parts[:-1]:
            current = os.open(component, directory_flags, dir_fd=current)
            descriptors.append(current)
        file_descriptor = os.open(parts[-1], os.O_RDONLY | no_follow, dir_fd=current)
        before = os.fstat(file_descriptor)
        if not stat.S_ISREG(before.st_mode):
            os.close(file_descriptor)
            raise ValueError("repository file must be regular")
        if before.st_size > _MAX_PUBLICATION_TRUST_INPUT_BYTES:
            os.close(file_descriptor)
            raise ValueError("repository trust input exceeds the size limit")
        with os.fdopen(file_descriptor, "rb") as handle:
            content = handle.read(_MAX_PUBLICATION_TRUST_INPUT_BYTES + 1)
            after = os.fstat(handle.fileno())
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity or len(content) != before.st_size:
            raise ValueError("repository trust input changed while being read")
        return content
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


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
        env=_git_environment(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=_GIT_TIMEOUT_SECONDS,
    )
    return result.returncode == 0


def _git_object_type(repo_root: Path, git: str, object_id: str) -> str | None:
    if _GIT_OBJECT_ID_PATTERN.fullmatch(object_id) is None:
        return None
    result = subprocess.run(  # noqa: S603 - validated Git object ID
        [git, "cat-file", "-t", object_id],
        cwd=repo_root,
        check=False,
        capture_output=True,
        env=_git_environment(),
        timeout=_GIT_TIMEOUT_SECONDS,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _git_tree_id(repo_root: Path, git: str, commit: str) -> str | None:
    if _GIT_OBJECT_ID_PATTERN.fullmatch(commit) is None:
        return None
    result = subprocess.run(  # noqa: S603 - validated Git commit ID
        [git, "rev-parse", f"{commit}^{{tree}}"],
        cwd=repo_root,
        check=False,
        capture_output=True,
        env=_git_environment(),
        timeout=_GIT_TIMEOUT_SECONDS,
        text=True,
    )
    tree = result.stdout.strip()
    return tree if result.returncode == 0 and _GIT_OBJECT_ID_PATTERN.fullmatch(tree) else None


def _git_path_object_id(
    repo_root: Path,
    git: str,
    commit: str,
    relative_path: str,
) -> str | None:
    if (
        _GIT_OBJECT_ID_PATTERN.fullmatch(commit) is None
        or _safe_relative_path(relative_path) is None
    ):
        return None
    result = subprocess.run(  # noqa: S603 - validated commit and literal repository path
        [git, "rev-parse", f"{commit}:{relative_path}"],
        cwd=repo_root,
        check=False,
        capture_output=True,
        env=_git_environment(),
        timeout=_GIT_TIMEOUT_SECONDS,
        text=True,
    )
    object_id = result.stdout.strip()
    return (
        object_id
        if result.returncode == 0 and _GIT_OBJECT_ID_PATTERN.fullmatch(object_id)
        else None
    )


def _verify_iter000_history(repo_root: Path, git: str, head: str) -> tuple[bool, str]:
    replacements = subprocess.run(  # noqa: S603 - fixed read-only Git command
        [git, "replace", "--list"],
        cwd=repo_root,
        check=False,
        capture_output=True,
        env=_git_environment(),
        timeout=_GIT_TIMEOUT_SECONDS,
        text=True,
    )
    if replacements.returncode != 0 or replacements.stdout.strip():
        return False, "Iteration history rejects configured Git replacement objects."
    history = (
        (_ITER000_TRIGGER_COMMIT, None),
        (_ITER000_ATTEMPT_001_EXECUTION_COMMIT, _ITER000_ATTEMPT_001_EXECUTION_TREE),
        (_ITER000_PROOF_COMMIT, _ITER000_PROOF_COMMIT_TREE),
        (_ITER000_VERIFICATION_CONTRACT_COMMIT, _ITER000_VERIFICATION_CONTRACT_TREE),
        (_ITER000_VERIFICATION_CORRECTION_COMMIT, _ITER000_VERIFICATION_CORRECTION_TREE),
    )
    for commit, expected_tree in history:
        if _git_object_type(repo_root, git, commit) != "commit":
            return False, f"Required historical commit is unavailable: {commit}."
        if expected_tree is not None and _git_tree_id(repo_root, git, commit) != expected_tree:
            return False, f"Historical commit tree differs: {commit}."
    for (parent, _), (child, _) in pairwise(history):
        if not _git_is_ancestor(repo_root, git, parent, child):
            return False, "Iteration history does not preserve the required ancestry chain."
    if not _git_is_ancestor(repo_root, git, history[-1][0], head):
        return False, "Verification amendment correction is not an ancestor of HEAD."
    if (
        _git_path_object_id(
            repo_root,
            git,
            _ITER000_ATTEMPT_001_EXECUTION_COMMIT,
            "src/fieldtrue",
        )
        != _ITER000_ATTEMPT_001_EXECUTION_SOURCE_TREE
    ):
        return False, "Historical execution source tree differs."
    return True, "Exact execution, proof, and amendment Git history is available."


def _verify_attempt_001_proof_preserved(
    repo_root: Path,
    git: str,
    head: str,
) -> tuple[bool, str]:
    if (
        _git_path_object_id(repo_root, git, _ITER000_PROOF_COMMIT, _ITER000_ATTEMPT_001_PROOF_PATH)
        != _ITER000_ATTEMPT_001_PROOF_TREE
        or _git_path_object_id(repo_root, git, head, _ITER000_ATTEMPT_001_PROOF_PATH)
        != _ITER000_ATTEMPT_001_PROOF_TREE
    ):
        return False, "Attempt 001 proof subtree differs from its preservation commit."
    critical_hashes = {
        _ITER000_ATTEMPT_001_AUTHORITY_PATH: _ITER000_ATTEMPT_001_AUTHORITY_SHA256,
        _ITER000_ATTEMPT_001_RECEIPT_PATH: _ITER000_ATTEMPT_001_CONSUMPTION_SHA256,
        f"{_ITER000_ATTEMPT_001_PROOF_PATH}/attempt_authority_consumption.json": (
            _ITER000_ATTEMPT_001_CONSUMPTION_SHA256
        ),
        f"{_ITER000_ATTEMPT_001_PROOF_PATH}/execution_ledger.jsonl": (
            _ITER000_ATTEMPT_001_LEDGER_SHA256
        ),
        f"{_ITER000_ATTEMPT_001_PROOF_PATH}/execution_ledger.head.json": (
            _ITER000_ATTEMPT_001_HEAD_SHA256
        ),
    }
    for relative, expected_hash in critical_hashes.items():
        path = repo_root / relative
        if (
            path.is_symlink()
            or not path.is_file()
            or sha256_bytes(path.read_bytes()) != expected_hash
        ):
            return False, f"Attempt 001 preserved evidence differs: {relative}."
        if _git_blob_at_path(repo_root, git, head, relative) != path.read_bytes():
            return False, f"Attempt 001 evidence is not committed at HEAD: {relative}."
    proof_root = repo_root / _ITER000_ATTEMPT_001_PROOF_PATH
    if proof_root.is_symlink() or not proof_root.is_dir():
        return False, "Attempt 001 proof root must be a regular directory."
    try:
        proof_entries = tuple(proof_root.iterdir())
    except OSError:
        return False, "Attempt 001 proof root is unreadable."
    if len(proof_entries) != 16 or any(
        path.is_symlink() or not path.is_file() for path in proof_entries
    ):
        return False, "Attempt 001 proof root must contain exactly sixteen regular files."
    status = subprocess.run(  # noqa: S603 - fixed read-only Git status
        [
            git,
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--",
            _ITER000_ATTEMPT_001_PROOF_PATH,
            _ITER000_ATTEMPT_001_RECEIPT_PATH,
            _ITER000_ATTEMPT_001_AUTHORITY_PATH,
        ],
        cwd=repo_root,
        check=False,
        capture_output=True,
        env=_git_environment(),
        timeout=_GIT_TIMEOUT_SECONDS,
    )
    if status.returncode != 0 or status.stdout:
        return False, "Attempt 001 proof or consumed authority has uncommitted changes."
    return True, "Attempt 001 proof and consumed execution authority remain byte-exact."


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
        env=_git_environment(),
        timeout=_GIT_TIMEOUT_SECONDS,
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
    surface_commit: str | None = None,
) -> tuple[bool, str]:
    selected_commit = surface_commit or head
    historical = selected_commit != head
    authority_path = repo_root / _ITER000_ATTEMPT_001_AUTHORITY_PATH
    try:
        authority_bytes = (
            _git_blob_at_path(
                repo_root,
                git,
                selected_commit,
                _ITER000_ATTEMPT_001_AUTHORITY_PATH,
            )
            if historical
            else authority_path.read_bytes()
        )
        authority = json.loads(authority_bytes) if authority_bytes is not None else None
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return False, f"Attempt 001 authority is unreadable: {type(error).__name__}."
    if not isinstance(authority, dict) or authority_bytes is None:
        return False, "Attempt 001 authority must contain a JSON object."
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
        if not historical:
            path = repo_root / relative
            if path.is_symlink() or not path.is_file():
                return False, f"Attempt 001 protocol input is not a regular file: {relative}."
        selected_bytes = (
            _git_blob_at_path(repo_root, git, selected_commit, relative)
            if historical
            else (repo_root / relative).read_bytes()
        )
        if selected_bytes is None or sha256_bytes(selected_bytes) != expected_hash:
            return False, f"Attempt 001 protocol hash mismatch: {relative}."
        if not historical and _git_blob_at_path(repo_root, git, head, relative) != selected_bytes:
            return False, f"Attempt 001 protocol input is not committed at HEAD: {relative}."
    if (
        _git_blob_at_path(repo_root, git, selected_commit, _ITER000_ATTEMPT_001_AUTHORITY_PATH)
        != authority_bytes
    ):
        return False, "Attempt 001 authority is not committed at its execution commit."

    try:
        if historical:
            anchor_bytes = _git_blob_at_path(repo_root, git, selected_commit, _ITER000_ANCHOR_PATH)
            anchor = (
                SignerAnchor.model_validate_json(anchor_bytes) if anchor_bytes is not None else None
            )
        else:
            anchor = load_signer_anchor(repo_root / _ITER000_ANCHOR_PATH)
    except (OSError, ValueError):
        return False, "Attempt 001 authority signer anchor is invalid."
    if anchor is None or anchor.signer_public_key != _ITER000_SIGNER_PUBLIC_KEY:
        return False, "Attempt 001 authority signer key differs from its frozen anchor."

    trigger_source_paths = _git_tree_paths(repo_root, git, _ITER000_TRIGGER_COMMIT, "src/fieldtrue")
    selected_source_paths = _git_tree_paths(repo_root, git, selected_commit, "src/fieldtrue")
    if trigger_source_paths is None or selected_source_paths is None:
        return False, "Attempt 001 cannot resolve the complete source surface."
    if not historical:
        working_source_paths = _working_source_paths(repo_root)
        if working_source_paths is None:
            return False, "Attempt 001 cannot resolve the complete source surface."
        selected_source_paths = working_source_paths
    if selected_source_paths != trigger_source_paths:
        return False, "Attempt 001 added, removed, or linked a source-surface file."

    for relative in sorted(trigger_source_paths):
        trigger_blob = _git_blob_at_path(repo_root, git, _ITER000_TRIGGER_COMMIT, relative)
        if trigger_blob is None:
            return False, f"Attempt 001 triggering source is unavailable: {relative}."
        selected_bytes = (
            _git_blob_at_path(repo_root, git, selected_commit, relative)
            if historical
            else (repo_root / relative).read_bytes()
        )
        if selected_bytes is None:
            return False, f"Attempt 001 execution source is unavailable: {relative}."
        if relative in _ITER000_ATTEMPT_001_AUTHORIZED_SOURCE_HASHES:
            before_hash, after_hash = _ITER000_ATTEMPT_001_AUTHORIZED_SOURCE_HASHES[relative]
            if (
                after_hash == "0" * 64
                or sha256_bytes(trigger_blob) != before_hash
                or sha256_bytes(selected_bytes) != after_hash
                or protocol_hashes.get(relative) != after_hash
            ):
                return False, f"Attempt 001 authorized source binding differs: {relative}."
            continue
        if relative in _ITER000_ATTEMPT_001_RECOVERY_PATHS:
            if protocol_hashes.get(relative) != sha256_bytes(selected_bytes):
                return False, f"Attempt 001 recovery control is not authority-bound: {relative}."
            continue
        if selected_bytes != trigger_blob:
            return False, f"Attempt 001 changed an unauthorized source file: {relative}."

    gate_control_blob = _git_blob_at_path(
        repo_root, git, _ITER000_TRIGGER_COMMIT, _ITER000_GATE_CONTROL_PATH
    )
    try:
        trigger_gate_control = (
            json.loads(gate_control_blob) if gate_control_blob is not None else None
        )
        selected_gate_blob = (
            _git_blob_at_path(
                repo_root,
                git,
                selected_commit,
                _ITER000_GATE_CONTROL_PATH,
            )
            if historical
            else (repo_root / _ITER000_GATE_CONTROL_PATH).read_bytes()
        )
        current_gate_control = (
            json.loads(selected_gate_blob) if selected_gate_blob is not None else None
        )
    except (OSError, ValueError, json.JSONDecodeError):
        return False, "Attempt 001 gate-control registry is unreadable."
    if not isinstance(trigger_gate_control, dict):
        return False, "Attempt 001 triggering gate-control registry is unavailable."
    if not isinstance(current_gate_control, dict):
        return False, "Attempt 001 execution gate-control registry is unavailable."
    trigger_gate_control.pop("execution_seal", None)
    current_gate_control.pop("execution_seal", None)
    if current_gate_control != trigger_gate_control:
        return False, "Attempt 001 changed the scientific gate-control contract."

    unchanged_protocol_paths = expected_protocol_paths - (
        _ITER000_ATTEMPT_001_RECOVERY_PATHS | set(_ITER000_ATTEMPT_001_AUTHORIZED_SOURCE_HASHES)
    )
    for relative in sorted(unchanged_protocol_paths):
        trigger_blob = _git_blob_at_path(repo_root, git, _ITER000_TRIGGER_COMMIT, relative)
        selected_bytes = (
            _git_blob_at_path(repo_root, git, selected_commit, relative)
            if historical
            else (repo_root / relative).read_bytes()
        )
        if trigger_blob != selected_bytes:
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
        "Historical attempt 001 authority binds the complete execution protocol and source "
        "surface; only the exact TLS and attempt-control changes are admitted.",
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

    try:
        git = _trusted_git(repo_root)
        head = subprocess.run(  # noqa: S603 - fixed Git command
            [git, "rev-parse", "HEAD"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            env=_git_environment(),
            timeout=_GIT_TIMEOUT_SECONDS,
            text=True,
        ).stdout.strip()
    except GitTrustError as error:
        return False, f"Amendment 001 Git trust failed: {error}."
    except (OSError, subprocess.SubprocessError, ValueError):
        return False, "Amendment 001 cannot resolve HEAD."
    if (
        _GIT_OBJECT_ID_PATTERN.fullmatch(head) is None
        or not _git_commit_resolves(repo_root, git, _ITER000_TRIGGER_COMMIT)
        or not _git_is_ancestor(repo_root, git, _ITER000_TRIGGER_COMMIT, head)
    ):
        return False, "Amendment 001 triggering commit is not an ancestor of HEAD."
    correction_history = _git_is_ancestor(
        repo_root,
        git,
        _ITER000_VERIFICATION_CORRECTION_COMMIT,
        head,
    )
    if correction_history:
        history_valid, history_detail = _verify_iter000_history(repo_root, git, head)
        if not history_valid:
            return False, history_detail
        correction_trust_inputs = {
            _ITER000_VERIFICATION_CONTRACT_PATH: _ITER000_VERIFICATION_CONTRACT_SHA256,
            _ITER000_VERIFICATION_CORRECTION_PATH: (_ITER000_VERIFICATION_CORRECTION_SHA256),
        }
        for relative, expected_hash in correction_trust_inputs.items():
            path = repo_root / relative
            if path.is_symlink() or not path.is_file():
                return False, f"Verification correction trust input is missing: {relative}."
            current_bytes = path.read_bytes()
            if sha256_bytes(current_bytes) != expected_hash:
                return False, f"Verification correction trust input differs: {relative}."
            if _git_blob_at_path(repo_root, git, head, relative) != current_bytes:
                return (
                    False,
                    f"Verification correction trust input is not committed at HEAD: {relative}.",
                )
        proof_valid, proof_detail = _verify_attempt_001_proof_preserved(repo_root, git, head)
        if not proof_valid:
            return False, proof_detail
    surface_valid, surface_detail = _verify_attempt_001_scientific_surface(
        repo_root,
        git=git,
        head=head,
        surface_commit=(_ITER000_ATTEMPT_001_EXECUTION_COMMIT if correction_history else None),
    )
    if not surface_valid:
        return False, surface_detail
    trust_inputs = [
        _AMENDMENT_001_PATH,
        _AMENDMENT_001_DOCUMENT_PATH,
        _ITER000_ATTEMPT_001_AUTHORITY_PATH,
        _ATTEMPT_000_LEDGER_PATH,
        _ATTEMPT_000_HEAD_PATH,
        _ITER000_ANCHOR_PATH,
        _ITER000_DATASET_PATH,
        _ITER000_HYPOTHESIS_PATH,
    ]
    if not correction_history:
        trust_inputs.extend(
            (
                "pyproject.toml",
                "uv.lock",
                "src/fieldtrue/adapters/adapt.py",
                "src/fieldtrue/experiment.py",
            )
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

    if correction_history:
        return (
            True,
            "Historical attempt 001 execution and its immutable proof verify against exact Git "
            "objects; current verifier code is evaluated under a separate authority.",
        )
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
    try:
        receipt_bytes = _read_repo_regular_file(repo_root, receipt_relative)
        anchor_bytes = _read_repo_regular_file(repo_root, anchor_relative)
        contract_bytes = _read_repo_regular_file(repo_root, "mission/contract.json")
        loop_bytes = _read_repo_regular_file(repo_root, "mission/loop.json")
        receipt = json.loads(receipt_bytes)
        contract = json.loads(contract_bytes)
        anchor = PublicationSignerAnchor.model_validate_json(anchor_bytes)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return False, f"Publication evidence is unreadable: {type(error).__name__}."
    if not isinstance(receipt, dict) or not isinstance(contract, dict):
        return False, "Publication receipt and mission contract must be JSON objects."
    if (
        canonical_json_pretty(receipt) != receipt_bytes
        or canonical_json_pretty(anchor) != anchor_bytes
        or canonical_json_pretty(contract) != contract_bytes
        or canonical_json_pretty(loop) != loop_bytes
    ):
        return False, "Publication trust inputs must use canonical JSON."
    if (
        anchor.anchor_id != _PUBLICATION_ANCHOR_ID
        or anchor.mission_id != "inbar"
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
    active_mission_id = contract.get("mission_id")
    if (
        receipt.get("schema_version") != "fieldtrue.publication-gate-receipt.v1"
        or active_mission_id != "inbar"
        or loop.get("mission_id") != active_mission_id
        or receipt.get("mission_id") != active_mission_id
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

    try:
        git = _trusted_git(repo_root)
        head = subprocess.run(  # noqa: S603 - fixed Git command
            [git, "rev-parse", "HEAD"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            env=_git_environment(),
            timeout=_GIT_TIMEOUT_SECONDS,
            text=True,
        ).stdout.strip()
    except GitTrustError as error:
        return False, f"Publication evidence Git trust failed: {error}."
    except (OSError, subprocess.SubprocessError, ValueError):
        return False, "Publication evidence cannot resolve HEAD."
    if _GIT_OBJECT_ID_PATTERN.fullmatch(head) is None:
        return False, "Publication evidence resolved an invalid HEAD."
    trust_inputs = (
        ("mission/contract.json", contract_bytes),
        ("mission/loop.json", loop_bytes),
        (receipt_relative, receipt_bytes),
        (anchor_relative, anchor_bytes),
    )
    for relative, expected_bytes in trust_inputs:
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
            or evidence_relative
            in {
                receipt_relative,
                anchor_relative,
                "mission/contract.json",
                "mission/loop.json",
            }
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
    try:
        stable = all(
            _read_repo_regular_file(repo_root, relative) == expected_bytes
            for relative, expected_bytes in trust_inputs
        )
    except (OSError, ValueError):
        stable = False
    if not stable:
        return False, "Publication trust input changed during verification."
    return True, "Publication authorization is signed and every gate has distinct Git evidence."


def validate_mission(repo_root: Path) -> MissionValidation:
    checks: list[ValidationCheck] = []
    contract = _json(repo_root / "mission" / "contract.json")
    loop = _json(repo_root / "mission" / "loop.json")
    identity = _json(repo_root / "mission" / "name.json")
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
            "active-identity",
            contract.get("mission_id") == "inbar"
            and contract.get("name") == "Inbar"
            and loop.get("mission_id") == "inbar"
            and identity.get("canonical_name") == "Inbar"
            and identity.get("canonical_slug") == "inbar"
            and contract.get("legacy_protocol_namespace") == "fieldtrue",
            "Current mission surfaces must identify Inbar while preserving the legacy "
            "protocol namespace.",
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
    try:
        acquisition_contract = load_acquisition_contract(
            repo_root / _ITER001_ACQUISITION_CONTRACT_PATH
        )
        verify_preregistration_binding(repo_root, acquisition_contract)
        acquisition_contract_valid = True
        acquisition_contract_detail = (
            "Iteration 001 acquisition contract matches its committed preregistration."
        )
    except (AcquisitionAuditError, OSError, ValueError) as error:
        acquisition_contract_valid = False
        acquisition_contract_detail = f"Iteration 001 acquisition contract failed: {error}"
    checks.append(
        _check(
            "iter001-acquisition-contract",
            acquisition_contract_valid,
            acquisition_contract_detail,
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
    if (repo_root / _ITER000_VERIFICATION_CONTRACT_PATH).is_file():
        from fieldtrue.verification import validate_iter000_verification_correction_surface

        correction_valid, correction_detail = validate_iter000_verification_correction_surface(
            repo_root
        )
        checks.append(
            _check(
                "verification-correction-001",
                correction_valid,
                correction_detail,
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
