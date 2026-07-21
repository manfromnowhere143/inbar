from __future__ import annotations

import hashlib
import os
import py_compile
import subprocess
import sys
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import fieldtrue.acquisition as acquisition_module
from fieldtrue.acquisition import (
    AcquisitionAdmissionReport,
    AcquisitionAuditError,
    AcquisitionCandidateRegistry,
    AcquisitionContract,
    ActorTrustRegistry,
    AdmissionControlSuiteReceipt,
    ArtifactBinding,
    AttestationSubjectKind,
    BoundReview,
    DiagnosticExecution,
    EvidencePlane,
    EvidenceSequenceReceipt,
    EvidenceTimeBinding,
    FieldPlaneAssignment,
    IncidentDossier,
    IncidentTimeline,
    InterventionComparatorRegistry,
    ModelVisibleLeakageScanReport,
    ModelVisibleProjection,
    PermissionDecision,
    PermissionKind,
    PhysicalProvenanceRecord,
    PlaneIncidentManifest,
    PlaneSeparationReceipt,
    ProtocolReviewRecord,
    ProtocolReviewRegistry,
    RecoveryExecution,
    ResourceUsage,
    ReviewPurpose,
    RoleKind,
    SettledOutcomeRecord,
    ShortcutBaselineReport,
    SourceManifest,
    SourceResource,
    TrustedActor,
    TruthCustodyReceipt,
    audit_acquisition,
    build_model_visible_leakage_scan,
    issue_actor_trust_registry,
    render_admission_result,
    verify_preregistration_binding,
    write_admission_output,
)
from fieldtrue.canonical import read_json, sha256_file, sha256_value, write_json
from fieldtrue.control_observation import record_control_observation
from fieldtrue.git_trust import git_environment, trusted_repository_git
from fieldtrue.splits import SplitUnit, freeze_group_split
from tests.acquisition_helpers import (
    ACTOR_KEYS,
    ANCHOR_KEY,
    BASE,
    _signed_model,
    acquisition_contract,
    build_acquisition_tree,
)


def _rewrite_bound_json(
    root: Path,
    dossier_path: Path,
    binding_field: str,
    mutate: object,
) -> None:
    dossier = read_json(dossier_path)
    binding = dossier[binding_field]
    artifact_path = root / binding["path"]
    value = read_json(artifact_path)
    assert callable(mutate)
    mutate(value)
    write_json(artifact_path, value)
    binding["sha256"] = sha256_file(artifact_path)
    binding["bytes"] = artifact_path.stat().st_size
    write_json(dossier_path, dossier)


def _aware(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _git(repo: Path, *arguments: str) -> str:
    return subprocess.run(  # noqa: S603 - test helper uses fixed Git and internal arguments
        ("/usr/bin/git", *arguments),
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _initialize_source_repository(repo: Path, files: dict[str, str]) -> str:
    for relative, content in files.items():
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    _git(repo, "init", "--quiet")
    _git(repo, "config", "user.name", "Acquisition Closure Test")
    _git(repo, "config", "user.email", "acquisition-closure@example.invalid")
    _git(repo, "add", ".")
    _git(repo, "commit", "--quiet", "-m", "seal source census")
    return _git(repo, "rev-parse", "HEAD")


def _source_census(
    repo: Path,
    authority_commit: str,
    repository_head: str,
    *,
    working_source_root: Path | None = None,
    working_source_private_read_only: bool = False,
) -> acquisition_module.AcquisitionSourceClosure:
    git = trusted_repository_git(repo)
    validator_path = repo / "src" / "fieldtrue" / "acquisition.py"
    return acquisition_module._acquisition_source_closure(
        git,
        repo,
        git_environment(),
        authority_commit=authority_commit,
        repository_head=repository_head,
        expected_validator_blob=_git(
            repo,
            "rev-parse",
            f"{authority_commit}:src/fieldtrue/acquisition.py",
        ),
        expected_validator_sha256=acquisition_module.sha256_bytes(validator_path.read_bytes()),
        working_source_root=working_source_root,
        working_source_private_read_only=working_source_private_read_only,
    )


def test_source_census_binds_from_package_child_module(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    authority = _initialize_source_repository(
        repo,
        {
            "src/fieldtrue/__init__.py": "",
            "src/fieldtrue/acquisition.py": "from fieldtrue.pkg import child\n",
            "src/fieldtrue/pkg/__init__.py": "",
            "src/fieldtrue/pkg/child.py": 'VALUE = "authority"\n',
        },
    )
    (repo / "src/fieldtrue/pkg/child.py").write_text('VALUE = "head"\n')
    _git(repo, "add", ".")
    _git(repo, "commit", "--quiet", "-m", "replace imported child")

    with pytest.raises(AcquisitionAuditError, match="source tree differs"):
        _source_census(repo, authority, _git(repo, "rev-parse", "HEAD"))


def test_source_census_rejects_module_package_resolution_collision(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    authority = _initialize_source_repository(
        repo,
        {
            "src/fieldtrue/__init__.py": "",
            "src/fieldtrue/acquisition.py": "import fieldtrue.dual\n",
            "src/fieldtrue/dual.py": 'VALUE = "module"\n',
            "src/fieldtrue/dual/__init__.py": 'VALUE = "authority-package"\n',
        },
    )
    (repo / "src/fieldtrue/dual/__init__.py").write_text('VALUE = "head-package"\n')
    _git(repo, "add", ".")
    _git(repo, "commit", "--quiet", "-m", "replace runtime-selected package")

    with pytest.raises(AcquisitionAuditError, match="source tree differs"):
        _source_census(repo, authority, _git(repo, "rev-parse", "HEAD"))


def test_source_census_binds_indirect_dynamic_import_target(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    authority = _initialize_source_repository(
        repo,
        {
            "src/fieldtrue/__init__.py": "",
            "src/fieldtrue/acquisition.py": (
                'import importlib\nloader = getattr(importlib, "import_module")\n'
                'loader("fieldtrue.hidden")\n'
            ),
            "src/fieldtrue/hidden.py": 'VALUE = "authority"\n',
        },
    )
    (repo / "src/fieldtrue/hidden.py").write_text('VALUE = "head"\n')
    _git(repo, "add", ".")
    _git(repo, "commit", "--quiet", "-m", "replace dynamic target")

    with pytest.raises(AcquisitionAuditError, match="source tree differs"):
        _source_census(repo, authority, _git(repo, "rev-parse", "HEAD"))


def test_source_census_rejects_ignored_sourceless_bytecode(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    authority = _initialize_source_repository(
        repo,
        {
            ".gitignore": "*.py[cod]\n__pycache__/\n",
            "src/fieldtrue/__init__.py": "",
            "src/fieldtrue/acquisition.py": (
                "try:\n import fieldtrue.hidden\nexcept ModuleNotFoundError:\n pass\n"
            ),
        },
    )
    bytecode_source = tmp_path / "hidden.py"
    bytecode_source.write_text('VALUE = "ignored"\n')
    py_compile.compile(
        str(bytecode_source),
        cfile=str(repo / "src/fieldtrue/hidden.pyc"),
        doraise=True,
    )
    assert (
        acquisition_module._clean_repository_status(
            trusted_repository_git(repo), repo, git_environment()
        )
        == b""
    )

    with pytest.raises(AcquisitionAuditError, match="working acquisition source census differs"):
        _source_census(repo, authority, authority)


def test_private_read_only_snapshot_requires_exact_source_mode_policy(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _initialize_source_repository(
        repo,
        {
            "src/fieldtrue/__init__.py": "",
            "src/fieldtrue/acquisition.py": "VALUE = 1\n",
            "src/fieldtrue/runner.py": "VALUE = 2\n",
        },
    )
    (repo / "src/fieldtrue/runner.py").chmod(0o755)
    _git(repo, "add", "src/fieldtrue/runner.py")
    _git(repo, "commit", "--quiet", "-m", "mark runner executable")
    authority = _git(repo, "rev-parse", "HEAD")

    snapshot = tmp_path / "snapshot"
    for relative, mode in (
        ("src/fieldtrue/__init__.py", 0o400),
        ("src/fieldtrue/acquisition.py", 0o400),
        ("src/fieldtrue/runner.py", 0o500),
    ):
        source = repo / relative
        target = snapshot / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
        target.chmod(mode)

    closure = _source_census(
        repo,
        authority,
        authority,
        working_source_root=snapshot,
        working_source_private_read_only=True,
    )
    assert {path: mode for path, mode, *_ in closure.sources} == {
        "src/fieldtrue/__init__.py": "100644",
        "src/fieldtrue/acquisition.py": "100644",
        "src/fieldtrue/runner.py": "100755",
    }

    with pytest.raises(AcquisitionAuditError, match="noncanonical permissions"):
        _source_census(repo, authority, authority, working_source_root=snapshot)

    (snapshot / "src/fieldtrue/runner.py").chmod(0o400)
    with pytest.raises(AcquisitionAuditError, match="working acquisition source census differs"):
        _source_census(
            repo,
            authority,
            authority,
            working_source_root=snapshot,
            working_source_private_read_only=True,
        )

    (snapshot / "src/fieldtrue/runner.py").chmod(0o440)
    with pytest.raises(AcquisitionAuditError, match="noncanonical permissions"):
        _source_census(
            repo,
            authority,
            authority,
            working_source_root=snapshot,
            working_source_private_read_only=True,
        )


def test_source_census_rejects_ignored_symlink_descendant(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    authority = _initialize_source_repository(
        repo,
        {
            ".gitignore": "src/fieldtrue/escape.py\n",
            "src/fieldtrue/__init__.py": "",
            "src/fieldtrue/acquisition.py": "VALUE = 1\n",
        },
    )
    (repo / "src/fieldtrue/escape.py").symlink_to("acquisition.py")
    assert (
        acquisition_module._clean_repository_status(
            trusted_repository_git(repo), repo, git_environment()
        )
        == b""
    )

    with pytest.raises(AcquisitionAuditError, match="not a regular file"):
        _source_census(repo, authority, authority)


def test_source_census_detects_file_replacement_during_descriptor_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    _initialize_source_repository(
        repo,
        {
            "src/fieldtrue/__init__.py": "",
            "src/fieldtrue/acquisition.py": "VALUE = 1\n",
            "src/fieldtrue/planning.py": "VALUE = 1\n",
        },
    )
    planning = repo / "src/fieldtrue/planning.py"
    original_open = acquisition_module.os.open
    replaced = False

    def racing_open(
        path: str | Path,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal replaced
        if path == "planning.py" and dir_fd is not None and not replaced:
            replaced = True
            planning.write_text("VALUE = 200\n")
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(acquisition_module.os, "open", racing_open)
    with pytest.raises(AcquisitionAuditError, match="changed during census"):
        acquisition_module._working_source_census(repo)


def test_source_census_rejects_hard_linked_source(tmp_path: Path) -> None:
    package = tmp_path / "src" / "fieldtrue"
    package.mkdir(parents=True)
    source = package / "acquisition.py"
    source.write_text("VALUE = 1\n")
    try:
        (tmp_path / "external-alias.py").hardlink_to(source)
    except OSError as error:
        pytest.fail(
            f"validation platform cannot create a hard link: {error}",
            pytrace=False,
        )

    with pytest.raises(AcquisitionAuditError, match="not a regular file"):
        acquisition_module._working_source_census(tmp_path)


def test_binding_file_rejects_replacement_between_lstat_and_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "binding.json"
    path.write_bytes(b"same-authorized-bytes")
    replacement = tmp_path / "replacement.json"
    replacement.write_bytes(path.read_bytes())
    original_open = acquisition_module.os.open
    replaced = False

    def racing_open(
        target: str | Path,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal replaced
        if Path(target) == path and not replaced:
            replaced = True
            replacement.replace(path)
        return original_open(target, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(acquisition_module.os, "open", racing_open)

    with pytest.raises(AcquisitionAuditError, match="changed while being read"):
        acquisition_module._read_binding_file(path, "test binding")


def test_bound_artifact_rejects_replacement_between_stat_and_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "artifact.bin"
    target.write_bytes(b"same-authorized-bytes")
    replacement = tmp_path / "replacement.bin"
    replacement.write_bytes(target.read_bytes())
    binding = ArtifactBinding(
        path=target.name,
        sha256=sha256_file(target),
        bytes=target.stat().st_size,
        media_type="application/octet-stream",
    )
    original_open = acquisition_module.os.open
    replaced = False

    def racing_open(
        path: str | Path,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal replaced
        if path == target.name and dir_fd is not None and not replaced:
            replaced = True
            replacement.replace(target)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(acquisition_module.os, "open", racing_open)

    with pytest.raises(AcquisitionAuditError, match="changed before open"):
        acquisition_module._verify_artifact(tmp_path, binding)


@pytest.mark.parametrize(
    "consumer",
    ["model", "json-leakage", "opaque-leakage", "ordered-chunks", "fingerprint"],
)
def test_artifact_consumers_reject_post_open_path_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    consumer: str,
) -> None:
    artifact_root = tmp_path / consumer
    artifact_root.mkdir()
    target = artifact_root / "artifact.bin"
    if consumer == "model":
        original_payload = (
            b'{"bytes":1,"media_type":"application/octet-stream",'
            b'"path":"original.bin","sha256":"' + b"a" * 64 + b'"}\n'
        )
        replacement_payload = original_payload.replace(b"original.bin", b"replaced.bin")
        media_type = "application/json"
    elif consumer == "json-leakage":
        original_payload = b'{"signal":"nominal"}\n'
        replacement_payload = b'{"fault_label":"incident-secret"}\n'
        media_type = "application/json"
    elif consumer == "opaque-leakage":
        original_payload = b"nominal-opaque-stream"
        replacement_payload = b"incident-secret-stream"
        media_type = "application/octet-stream"
    elif consumer == "fingerprint":
        original_payload = b"a" * (acquisition_module._FINGERPRINT_SAMPLE_BYTES + 4096)
        replacement_payload = b"b" * len(original_payload)
        media_type = "application/octet-stream"
    else:
        original_payload = b"ordered-source-stream" * 64
        replacement_payload = b"substitute-byte-stream" * 64
        media_type = "application/octet-stream"
    target.write_bytes(original_payload)
    replacement = artifact_root / "replacement.bin"
    replacement.write_bytes(replacement_payload)
    binding = ArtifactBinding(
        path=f"{consumer}/artifact.bin",
        sha256=sha256_file(target),
        bytes=len(original_payload),
        media_type=media_type,
    )
    original_fdopen = acquisition_module.os.fdopen
    replaced = False

    def racing_fdopen(
        descriptor: int,
        mode: str,
        *,
        closefd: bool = True,
    ) -> Any:
        nonlocal replaced
        handle = original_fdopen(descriptor, mode, closefd=closefd)
        if not replaced:
            replaced = True
            target.replace(artifact_root / "verified-original.bin")
            replacement.replace(target)
        return handle

    monkeypatch.setattr(acquisition_module.os, "fdopen", racing_fdopen)

    def consume() -> object:
        if consumer == "model":
            return acquisition_module._load_bound_model(tmp_path, binding, ArtifactBinding)
        if consumer in {"json-leakage", "opaque-leakage"}:
            return build_model_visible_leakage_scan(
                tmp_path,
                incident_id="incident-race",
                artifacts=(binding,),
                identity_values=("incident-secret",),
            )
        if consumer == "ordered-chunks":
            return acquisition_module._ordered_chunk_hashes(tmp_path, binding, 64)
        return acquisition_module._bounded_artifact_sample(tmp_path, binding)

    with pytest.raises(AcquisitionAuditError, match="changed while consumed"):
        consume()


def test_bound_artifact_rejects_ancestor_replacement_after_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_directory = tmp_path / "artifacts"
    artifact_directory.mkdir()
    target = artifact_directory / "model.json"
    target.write_bytes(b'{"path":"a","sha256":"' + b"a" * 64 + b'","bytes":1,"media_type":"x"}')
    replacement_directory = tmp_path / "replacement-artifacts"
    replacement_directory.mkdir()
    (replacement_directory / target.name).write_bytes(
        b'{"path":"b","sha256":"' + b"b" * 64 + b'","bytes":2,"media_type":"y"}'
    )
    binding = ArtifactBinding(
        path="artifacts/model.json",
        sha256=sha256_file(target),
        bytes=target.stat().st_size,
        media_type="application/json",
    )
    original_open = acquisition_module.os.open
    replaced = False

    def racing_open(
        path: str | Path,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal replaced
        descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
        if path == target.name and dir_fd is not None and not replaced:
            replaced = True
            artifact_directory.replace(tmp_path / "verified-artifacts")
            replacement_directory.replace(artifact_directory)
        return descriptor

    monkeypatch.setattr(acquisition_module.os, "open", racing_open)

    with pytest.raises(AcquisitionAuditError, match="artifact path changed while consumed"):
        acquisition_module._load_bound_model(tmp_path, binding, ArtifactBinding)


def test_bound_model_rejects_artifact_above_parse_byte_ceiling(tmp_path: Path) -> None:
    target = tmp_path / "oversized-model.json"
    with target.open("wb") as handle:
        handle.truncate(acquisition_module._MAX_BOUND_MODEL_BYTES + 1)
    binding = ArtifactBinding(
        path=target.name,
        sha256="0" * 64,
        bytes=target.stat().st_size,
        media_type="application/json",
    )

    with pytest.raises(AcquisitionAuditError, match="exceeds its consumption bound"):
        acquisition_module._load_bound_model(tmp_path, binding, ArtifactBinding)


def test_source_census_rejects_special_file(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.fail("validation platform does not provide POSIX FIFOs", pytrace=False)
    package = tmp_path / "src" / "fieldtrue"
    package.mkdir(parents=True)
    (package / "acquisition.py").write_text("VALUE = 1\n")
    try:
        os.mkfifo(package / "stream.py")
    except OSError as error:
        pytest.fail(
            f"validation platform cannot create a FIFO: {error}",
            pytrace=False,
        )

    with pytest.raises(AcquisitionAuditError, match="not a regular file"):
        acquisition_module._working_source_census(tmp_path)


def test_source_census_detects_directory_insertion_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / "src" / "fieldtrue"
    package.mkdir(parents=True)
    (package / "acquisition.py").write_text("VALUE = 1\n")
    package_metadata = package.stat()
    package_identity = (package_metadata.st_dev, package_metadata.st_ino)
    original_fstat = acquisition_module.os.fstat
    package_observations = 0

    def racing_fstat(descriptor: int) -> os.stat_result:
        nonlocal package_observations
        metadata = original_fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) == package_identity:
            package_observations += 1
            if package_observations == 2:
                (package / "late.py").write_text("VALUE = 2\n")
                metadata = original_fstat(descriptor)
        return metadata

    monkeypatch.setattr(acquisition_module.os, "fstat", racing_fstat)
    with pytest.raises(AcquisitionAuditError, match="directory changed during census"):
        acquisition_module._working_source_census(tmp_path)


def test_source_census_detects_directory_replacement_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / "src" / "fieldtrue"
    child = package / "pkg"
    child.mkdir(parents=True)
    (package / "acquisition.py").write_text("VALUE = 1\n")
    (child / "module.py").write_text("VALUE = 2\n")
    child_metadata = child.stat()
    child_identity = (child_metadata.st_dev, child_metadata.st_ino)
    original_fstat = acquisition_module.os.fstat
    child_observations = 0

    def racing_fstat(descriptor: int) -> os.stat_result:
        nonlocal child_observations
        metadata = original_fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) == child_identity:
            child_observations += 1
            if child_observations == 2:
                child.rename(package / "pkg-original")
                child.mkdir()
                (child / "module.py").write_text("VALUE = 2\n")
        return metadata

    monkeypatch.setattr(acquisition_module.os, "fstat", racing_fstat)
    with pytest.raises(AcquisitionAuditError, match="directory changed during census"):
        acquisition_module._working_source_census(tmp_path)


@pytest.mark.parametrize(
    ("limit_name", "expected_error"),
    [
        ("_MAX_ACQUISITION_SOURCE_DESCENDANTS", "descendant ceiling"),
        ("_MAX_ACQUISITION_SOURCE_FILES", "file ceiling"),
        ("_MAX_ACQUISITION_SOURCE_TOTAL_BYTES", "total byte ceiling"),
    ],
)
def test_working_source_census_enforces_resource_ceilings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    limit_name: str,
    expected_error: str,
) -> None:
    package = tmp_path / "src" / "fieldtrue"
    package.mkdir(parents=True)
    (package / "acquisition.py").write_text("VALUE = 1\n")
    (package / "planning.py").write_text("VALUE = 2\n")
    monkeypatch.setattr(acquisition_module, limit_name, 1)

    with pytest.raises(AcquisitionAuditError, match=expected_error):
        acquisition_module._working_source_census(tmp_path)


def test_git_source_contents_rejects_malformed_batch_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    blob = "a" * 40
    responses = iter(
        (
            subprocess.CompletedProcess(
                args=("git", "cat-file", "--batch-check"),
                returncode=0,
                stdout=f"{blob} blob 1\n".encode("ascii"),
                stderr=b"",
            ),
            subprocess.CompletedProcess(
                args=("git", "cat-file", "--batch"),
                returncode=0,
                stdout=f"{blob} blob 1\nx".encode("ascii"),
                stderr=b"",
            ),
        )
    )

    def fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return next(responses)

    monkeypatch.setattr(acquisition_module.subprocess, "run", fake_run)
    census = (("src/fieldtrue/acquisition.py", "100644", blob),)
    with pytest.raises(AcquisitionAuditError, match="content census is incoherent"):
        acquisition_module._git_source_contents("/usr/bin/git", tmp_path, {}, census)


def test_acquisition_source_closure_rejects_dirty_and_later_committed_planner(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    package = repo / "src" / "fieldtrue"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("\n")
    acquisition_path = package / "acquisition.py"
    acquisition_path.write_text("from fieldtrue.planning import select\n")
    planning_path = package / "planning.py"
    original_planning = "from fieldtrue.domain import VALUE\nselect = VALUE\n"
    planning_path.write_text(original_planning)
    (package / "domain.py").write_text("VALUE = 1\n")
    _git(repo, "init", "--quiet")
    _git(repo, "config", "user.name", "Acquisition Closure Test")
    _git(repo, "config", "user.email", "acquisition-closure@example.invalid")
    _git(repo, "add", ".")
    _git(repo, "commit", "--quiet", "-m", "seal source closure")

    git = trusted_repository_git(repo)
    environment = git_environment()
    authority_commit = _git(repo, "rev-parse", "HEAD")
    validator_blob = _git(repo, "rev-parse", "HEAD:src/fieldtrue/acquisition.py")
    validator_sha256 = acquisition_module.sha256_bytes(acquisition_path.read_bytes())
    closure = acquisition_module._acquisition_source_closure(
        git,
        repo,
        environment,
        authority_commit=authority_commit,
        repository_head=authority_commit,
        expected_validator_blob=validator_blob,
        expected_validator_sha256=validator_sha256,
    )
    assert tuple(item[0] for item in closure.sources) == (
        "src/fieldtrue/__init__.py",
        "src/fieldtrue/acquisition.py",
        "src/fieldtrue/domain.py",
        "src/fieldtrue/planning.py",
    )
    assert acquisition_module._clean_repository_status(git, repo, environment) == b""

    planning_path.write_text(original_planning + "select = 0\n")
    assert acquisition_module._clean_repository_status(git, repo, environment)
    with pytest.raises(
        AcquisitionAuditError,
        match="working acquisition source census differs",
    ):
        acquisition_module._acquisition_source_closure(
            git,
            repo,
            environment,
            authority_commit=authority_commit,
            repository_head=authority_commit,
            expected_validator_blob=validator_blob,
            expected_validator_sha256=validator_sha256,
        )

    _git(repo, "add", "src/fieldtrue/planning.py")
    assert acquisition_module._clean_repository_status(git, repo, environment)
    _git(repo, "commit", "--quiet", "-m", "replace planner after seal")
    changed_head = _git(repo, "rev-parse", "HEAD")
    with pytest.raises(
        AcquisitionAuditError,
        match="source tree differs",
    ):
        acquisition_module._acquisition_source_closure(
            git,
            repo,
            environment,
            authority_commit=authority_commit,
            repository_head=changed_head,
            expected_validator_blob=validator_blob,
            expected_validator_sha256=validator_sha256,
        )


def test_sealed_binding_rejects_dirty_staged_and_post_seal_planning_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(acquisition_module, "_isolated_launcher_flags_present", lambda: True)
    monkeypatch.setattr(
        acquisition_module,
        "_executing_validator_matches_source",
        lambda *_: True,
    )
    source_repo = Path(__file__).resolve().parents[2]
    repo = tmp_path / "repo"
    _git(tmp_path, "clone", "--quiet", "--no-hardlinks", str(source_repo), str(repo))
    _git(repo, "config", "user.name", "Acquisition Binding Test")
    _git(repo, "config", "user.email", "acquisition-binding@example.invalid")

    contract_path = repo / "protocol" / "acquisition" / "iter001_contract.json"
    contract_value = read_json(contract_path)
    validator_path = repo / "src" / "fieldtrue" / "acquisition.py"
    contract_value.update(
        {
            "control_authority_status": "sealed",
            "validator_git_blob": _git(
                repo,
                "rev-parse",
                "HEAD:src/fieldtrue/acquisition.py",
            ),
            "validator_source_sha256": sha256_file(validator_path),
            "dependency_lock_sha256": sha256_file(repo / "uv.lock"),
            "control_suite_sha256": "1" * 64,
        }
    )
    contract = AcquisitionContract.model_validate(contract_value)
    write_json(contract_path, contract)
    _git(repo, "add", "protocol/acquisition/iter001_contract.json")
    _git(repo, "commit", "--quiet", "-m", "seal acquisition authority")
    execution_commit = _git(repo, "rev-parse", "HEAD")

    closure = verify_preregistration_binding(repo, contract, execution_commit)
    assert any(path == "src/fieldtrue/planning.py" for path, *_ in closure.sources)

    planning_path = repo / "src" / "fieldtrue" / "planning.py"
    planning_path.write_bytes(planning_path.read_bytes() + b"\n# injected planner\n")
    with pytest.raises(AcquisitionAuditError, match="requires a clean repository"):
        verify_preregistration_binding(repo, contract, execution_commit)

    _git(repo, "add", "src/fieldtrue/planning.py")
    with pytest.raises(AcquisitionAuditError, match="Git preregistration trust failed"):
        verify_preregistration_binding(repo, contract, execution_commit)

    _git(repo, "commit", "--quiet", "-m", "replace planner after authority seal")
    with pytest.raises(
        AcquisitionAuditError,
        match="source tree differs",
    ):
        verify_preregistration_binding(repo, contract, execution_commit)


def test_sealed_binding_rejects_ordinary_interpreter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = Path(__file__).resolve().parents[2]
    contract_path = repo / "protocol" / "acquisition" / "iter001_contract.json"
    contract_value = read_json(contract_path)
    contract_value.update(
        {
            "control_authority_status": "sealed",
            "validator_git_blob": "1" * 40,
            "control_suite_sha256": "1" * 64,
        }
    )
    contract = AcquisitionContract.model_validate(contract_value)
    original_read_binding_file = acquisition_module._read_binding_file

    def sealed_contract(path: Path, label: str) -> bytes:
        if path == contract_path:
            return contract.model_dump_json().encode("utf-8")
        return original_read_binding_file(path, label)

    monkeypatch.setattr(acquisition_module, "_read_binding_file", sealed_contract)
    assert not acquisition_module._isolated_launcher_flags_present()
    with pytest.raises(AcquisitionAuditError, match="isolated launcher process flags"):
        verify_preregistration_binding(repo, contract)


def test_sealed_binding_rejects_disconnected_preregistration_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(acquisition_module, "_isolated_launcher_flags_present", lambda: True)
    monkeypatch.setattr(
        acquisition_module,
        "_executing_validator_matches_source",
        lambda *_: True,
    )
    source_repo = Path(__file__).resolve().parents[2]
    repo = tmp_path / "repo"
    _git(tmp_path, "clone", "--quiet", "--no-hardlinks", str(source_repo), str(repo))
    _git(repo, "config", "user.name", "Acquisition Ancestry Test")
    _git(repo, "config", "user.email", "acquisition-ancestry@example.invalid")
    disconnected = _git(
        repo,
        "commit-tree",
        _git(repo, "rev-parse", "HEAD^{tree}"),
        "-m",
        "disconnected preregistration",
    )
    _git(repo, "checkout", "--quiet", "--detach", disconnected)

    contract_path = repo / "protocol" / "acquisition" / "iter001_contract.json"
    contract_value = read_json(contract_path)
    contract_value.update(
        {
            "control_authority_status": "sealed",
            "validator_git_blob": _git(
                repo,
                "rev-parse",
                "HEAD:src/fieldtrue/acquisition.py",
            ),
            "validator_source_sha256": sha256_file(repo / "src" / "fieldtrue" / "acquisition.py"),
            "dependency_lock_sha256": sha256_file(repo / "uv.lock"),
            "control_suite_sha256": "1" * 64,
        }
    )
    contract = AcquisitionContract.model_validate(contract_value)
    write_json(contract_path, contract)
    _git(repo, "add", "protocol/acquisition/iter001_contract.json")
    _git(repo, "commit", "--quiet", "-m", "seal disconnected authority")

    with pytest.raises(AcquisitionAuditError, match="not control execution ancestry"):
        verify_preregistration_binding(repo, contract, _git(repo, "rev-parse", "HEAD"))


def test_isolated_python_flags_can_satisfy_launcher_contract() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-S",
            "-c",
            (
                "import sys; f=sys.flags; "
                "assert f.isolated == f.no_site == f.ignore_environment == 1; "
                "assert f.safe_path is True and f.dont_write_bytecode == 1"
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_executing_validator_honestly_matches_current_source() -> None:
    repo = Path(__file__).resolve().parents[2]
    source = (repo / "src/fieldtrue/acquisition.py").read_bytes()
    assert acquisition_module._executing_validator_matches_source(repo, source)
    altered = source.replace(b'"--untracked-files=all"', b'"--untracked-files=no"')
    assert altered != source
    assert not acquisition_module._executing_validator_matches_source(repo, altered)


def test_preregistration_binding_maps_git_timeout_to_audit_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = Path(__file__).resolve().parents[2]
    contract_path = repo / "protocol" / "acquisition" / "iter001_contract.json"
    contract_value = read_json(contract_path)
    contract_value["control_authority_status"] = "sealed"
    contract_value["validator_git_blob"] = "1" * 40
    contract_value["control_suite_sha256"] = "1" * 64
    contract = AcquisitionContract.model_validate(contract_value)
    original_read_binding_file = acquisition_module._read_binding_file

    def sealed_contract(path: Path, label: str) -> bytes:
        if path == contract_path:
            return contract.model_dump_json().encode("utf-8")
        return original_read_binding_file(path, label)

    monkeypatch.setattr(acquisition_module, "_read_binding_file", sealed_contract)
    monkeypatch.setattr(acquisition_module, "_isolated_launcher_flags_present", lambda: True)
    monkeypatch.setattr(
        acquisition_module,
        "trusted_repository_git",
        lambda _repo: "/usr/bin/git",
    )

    def timeout(*_args: object, **_kwargs: object) -> None:
        raise acquisition_module.subprocess.TimeoutExpired(cmd="git", timeout=10)

    monkeypatch.setattr(acquisition_module.subprocess, "run", timeout)
    with pytest.raises(AcquisitionAuditError, match="failed to run"):
        verify_preregistration_binding(repo, contract)


def _rewrite_signed_bound_json(
    root: Path,
    dossier_path: Path,
    binding_field: str,
    model: type[Any],
    *,
    subject_kind: AttestationSubjectKind,
    signer_role: RoleKind,
    issued_at_field: str,
    mutate: Any,
) -> None:
    dossier = read_json(dossier_path)
    binding = dossier[binding_field]
    artifact_path = root / binding["path"]
    body = read_json(artifact_path)
    original_attestation = body["attestation"]
    body.pop("attestation")
    mutate(body)
    signed = _signed_model(
        model,
        body,
        subject_kind=subject_kind,
        signing_key=ACTOR_KEYS[signer_role],
        signer_id=f"actor-{signer_role.value}",
        attestation_id=f"negative-control-{binding_field}",
        issued_at=(
            _aware(original_attestation["issued_at"])
            if issued_at_field == "attestation.issued_at"
            else _aware(body[issued_at_field])
        ),
    )
    write_json(artifact_path, signed)
    binding["sha256"] = sha256_file(artifact_path)
    binding["bytes"] = artifact_path.stat().st_size
    write_json(dossier_path, dossier)


def _integrity_failures(report: AcquisitionAdmissionReport) -> list[str]:
    gate = next(gate for gate in report.gates if gate.gate_id == "artifact-integrity")
    return gate.observed["failures"]


def _replace_bound_bytes(root: Path, binding: dict[str, Any], payload: bytes) -> None:
    relative_path = binding.get("path", binding.get("uri"))
    assert isinstance(relative_path, str)
    artifact_path = root / relative_path
    artifact_path.write_bytes(payload)
    binding["sha256"] = sha256_file(artifact_path)
    binding["bytes"] = artifact_path.stat().st_size


def _refresh_split_locks(root: Path) -> None:
    dossiers = [read_json(path) for path in sorted((root / "dossiers").glob("*.json"))]
    units = [
        SplitUnit(
            incident_id=dossier["group"]["incident_id"],
            hardware_family=dossier["group"]["system_family"],
            hardware_id=dossier["group"]["hardware_id"],
            mission_id=dossier["group"]["mission_id"],
            fault_family=dossier["group"]["fault_family"],
            evidence_hash=dossier["evidence_bundle"]["sha256"],
            truth_hash=dossier["truth_record"]["sha256"],
        )
        for dossier in dossiers
    ]
    registry_path = root / "split_locks.json"
    registry = read_json(registry_path)
    for axis in ("hardware_family", "hardware_identity", "fault_family"):
        binding = registry[axis]
        lock_path = root / binding["path"]
        previous = read_json(lock_path)
        lock = freeze_group_split(
            units,
            seed=previous["seed"],
            holdout_dimensions=tuple(previous["holdout_dimensions"]),
        )
        write_json(lock_path, lock)
        binding["sha256"] = sha256_file(lock_path)
        binding["bytes"] = lock_path.stat().st_size
    write_json(registry_path, registry)


def _identity_payload(dossier: dict[str, Any], stream: str, repetitions: int) -> bytes:
    group = dossier["group"]
    identities = (
        group["incident_id"],
        group["root_incident_group_id"],
        group["acquisition_session_id"],
        group["independence_group_id"],
        group["acquisition_lineage_id"],
        group["hardware_id"],
        group["configuration_id"],
        group["environment_id"],
        group["mission_id"],
        group["site_id"],
    )
    row = f"{stream}|{'|'.join(identities)}|calibrated-signal\n".encode()
    return row * repetitions


def _resign_evidence_sequence(
    root: Path,
    dossier: dict[str, Any],
    evidence: dict[str, Any],
) -> None:
    sequence_path = root / dossier["evidence_sequence"]["path"]
    sequence = read_json(sequence_path)
    sequence.pop("attestation")
    evidence_by_id = {item["evidence_id"]: item for item in evidence["evidence"]}
    for stream in sequence["streams"]:
        artifact = evidence_by_id[stream["evidence_id"]]["artifact"]
        payload = (root / artifact["uri"]).read_bytes()
        stream["artifact_sha256"] = artifact["sha256"]
        stream["artifact_bytes"] = artifact["bytes"]
        stream["ordered_chunk_sha256"] = [
            hashlib.sha256(payload[offset : offset + stream["chunk_bytes"]]).hexdigest()
            for offset in range(0, len(payload), stream["chunk_bytes"])
        ]
    signed_sequence = _signed_model(
        EvidenceSequenceReceipt,
        sequence,
        subject_kind=AttestationSubjectKind.EVIDENCE_SEQUENCE,
        signing_key=ACTOR_KEYS[RoleKind.SOURCE_STEWARD],
        signer_id=f"actor-{RoleKind.SOURCE_STEWARD.value}",
        attestation_id=f"resigned-{dossier['group']['incident_id']}-evidence-sequence",
        issued_at=_aware(sequence["produced_at"]),
    )
    write_json(sequence_path, signed_sequence)
    dossier["evidence_sequence"]["sha256"] = sha256_file(sequence_path)
    dossier["evidence_sequence"]["bytes"] = sequence_path.stat().st_size


def _refresh_model_visible_leakage_scan(root: Path, dossier_path: Path) -> None:
    dossier = read_json(dossier_path)
    source = read_json(root / "sources" / "physical-source.json")
    truth = read_json(root / dossier["truth_record"]["path"])
    group = dossier["group"]
    projection_path = root / dossier["model_visible_projection"]["path"]
    projection = read_json(projection_path)
    projection.pop("attestation")
    artifacts = tuple(
        ArtifactBinding.model_validate(binding) for binding in projection["model_input_artifacts"]
    )
    scan = build_model_visible_leakage_scan(
        root,
        incident_id=group["incident_id"],
        artifacts=artifacts,
        identity_values=(
            group["incident_id"],
            group["root_incident_group_id"],
            group["acquisition_session_id"],
            group["independence_group_id"],
            group["acquisition_lineage_id"],
            group["system_family"],
            group["hardware_id"],
            group["fault_family"],
            group["configuration_id"],
            group["environment_id"],
            group["mission_id"],
            group["site_id"],
            source["source_id"],
            source["source_authority"],
            source["source_version"],
            *(resource["resource_id"] for resource in source["resources"]),
            truth["commitment_nonce"],
            truth["hardware_family"],
            truth["hardware_id"],
            truth["fault_family"],
            *truth["mechanism_ids"],
            truth["cause_authority"],
        ),
    )
    scan_path = root / projection["leakage_scan"]["path"]
    write_json(scan_path, scan)
    projection["leakage_scan"]["sha256"] = sha256_file(scan_path)
    projection["leakage_scan"]["bytes"] = scan_path.stat().st_size
    projection["leakage_detected"] = scan.leakage_detected
    signed_projection = _signed_model(
        ModelVisibleProjection,
        projection,
        subject_kind=AttestationSubjectKind.MODEL_VISIBLE_PROJECTION,
        signing_key=ACTOR_KEYS[RoleKind.EVIDENCE_CURATOR],
        signer_id=f"actor-{RoleKind.EVIDENCE_CURATOR.value}",
        attestation_id=f"refreshed-{group['incident_id']}-projection-scan",
        issued_at=_aware(projection["projected_at"]),
    )
    write_json(projection_path, signed_projection)
    dossier["model_visible_projection"]["sha256"] = sha256_file(projection_path)
    dossier["model_visible_projection"]["bytes"] = projection_path.stat().st_size
    write_json(dossier_path, dossier)


def _rewrite_evidence_bundle_and_projection(
    root: Path,
    dossier_path: Path,
    mutate: Any,
) -> None:
    dossier = read_json(dossier_path)
    evidence_path = root / dossier["evidence_bundle"]["path"]
    evidence = read_json(evidence_path)
    mutate(evidence)
    write_json(evidence_path, evidence)
    dossier["evidence_bundle"]["sha256"] = sha256_file(evidence_path)
    dossier["evidence_bundle"]["bytes"] = evidence_path.stat().st_size

    projection_path = root / dossier["model_visible_projection"]["path"]
    projection = read_json(projection_path)
    projection.pop("attestation")
    projection["evidence_bundle_sha256"] = sha256_value(evidence)
    signed_projection = _signed_model(
        ModelVisibleProjection,
        projection,
        subject_kind=AttestationSubjectKind.MODEL_VISIBLE_PROJECTION,
        signing_key=ACTOR_KEYS[RoleKind.EVIDENCE_CURATOR],
        signer_id=f"actor-{RoleKind.EVIDENCE_CURATOR.value}",
        attestation_id=f"rewritten-{dossier['group']['incident_id']}-projection",
        issued_at=_aware(projection["projected_at"]),
    )
    write_json(projection_path, signed_projection)
    dossier["model_visible_projection"]["sha256"] = sha256_file(projection_path)
    dossier["model_visible_projection"]["bytes"] = projection_path.stat().st_size
    write_json(dossier_path, dossier)


def _replace_model_streams_with_identity_normalized_content(
    root: Path,
    dossier_path: Path,
) -> None:
    dossier = read_json(dossier_path)
    evidence_path = root / dossier["evidence_bundle"]["path"]
    evidence = read_json(evidence_path)
    projection_path = root / dossier["model_visible_projection"]["path"]
    projection = read_json(projection_path)
    projection.pop("attestation")
    suffix = dossier["group"]["incident_id"][-1].encode()
    shared_telemetry = hashlib.shake_256(b"shared-telemetry-control").hexdigest(2048).encode()
    shared_commands = hashlib.shake_256(b"shared-command-control").hexdigest(1024).encode()
    payloads = (
        b'{"samples_hex":"' + shared_telemetry + suffix + b'"}\n',
        b'{"relay_trace":"' + shared_commands + suffix + b'"}\n',
    )
    for index, payload in enumerate(payloads):
        evidence_binding = evidence["evidence"][index]["artifact"]
        _replace_bound_bytes(root, evidence_binding, payload)
        projection_binding = projection["model_input_artifacts"][index]
        projection_binding["sha256"] = evidence_binding["sha256"]
        projection_binding["bytes"] = evidence_binding["bytes"]

    write_json(evidence_path, evidence)
    dossier["evidence_bundle"]["sha256"] = sha256_file(evidence_path)
    dossier["evidence_bundle"]["bytes"] = evidence_path.stat().st_size
    _resign_evidence_sequence(root, dossier, evidence)
    projection["evidence_bundle_sha256"] = sha256_value(evidence)
    signed_projection = _signed_model(
        ModelVisibleProjection,
        projection,
        subject_kind=AttestationSubjectKind.MODEL_VISIBLE_PROJECTION,
        signing_key=ACTOR_KEYS[RoleKind.EVIDENCE_CURATOR],
        signer_id=f"actor-{RoleKind.EVIDENCE_CURATOR.value}",
        attestation_id=f"normalized-{dossier['group']['incident_id']}-projection",
        issued_at=_aware(projection["projected_at"]),
    )
    write_json(projection_path, signed_projection)
    dossier["model_visible_projection"]["sha256"] = sha256_file(projection_path)
    dossier["model_visible_projection"]["bytes"] = projection_path.stat().st_size
    write_json(dossier_path, dossier)
    _refresh_model_visible_leakage_scan(root, dossier_path)


def _set_v1_shortcut_resolution(root: Path) -> None:
    path = root / "shortcut_baseline.json"
    body = read_json(path)
    body.pop("attestation")
    body["results"][0]["resolves_mechanism_without_action"] = True
    report = _signed_model(
        ShortcutBaselineReport,
        body,
        subject_kind=AttestationSubjectKind.SHORTCUT_BASELINE,
        signing_key=ACTOR_KEYS[RoleKind.STATISTICIAN],
        signer_id=f"actor-{RoleKind.STATISTICIAN.value}",
        attestation_id="negative-control-resolving-shortcut",
        issued_at=_aware(body["evaluated_at"]),
    )
    write_json(path, report)


def test_complete_conjunctive_pilot_passes(tmp_path: Path) -> None:
    contract = build_acquisition_tree(tmp_path)
    report = audit_acquisition(contract, tmp_path)
    record_control_observation(tmp_path, report)

    assert report.authority_profile == "test_fixture"
    assert report.verdict == "PASS_PILOT"
    assert len(report.eligible_incident_ids) == 30
    assert {gate.status for gate in report.gates} == {"pass"}
    coverage = next(gate for gate in report.gates if gate.gate_id == "conjunctive-coverage")
    assert coverage.observed["system_families"] == {
        "system-family-0": 10,
        "system-family-1": 10,
        "system-family-2": 10,
    }
    assert coverage.observed["maximum_share"] == 0.4


def test_v1_audit_rejects_canonical_authority_before_shortcut_consumption(
    tmp_path: Path,
) -> None:
    contract = acquisition_contract()
    mismatched = contract.model_copy(update={"authority_profile": "canonical"})

    assert not (tmp_path / "shortcut_baseline.json").exists()
    with pytest.raises(
        AcquisitionAuditError,
        match=r"^V1 shortcut reports cannot authorize a canonical verdict$",
    ):
        audit_acquisition(mismatched, tmp_path)


def test_audit_rejects_fixture_receipt_under_a_different_authority_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = build_acquisition_tree(tmp_path)
    control_suite = AdmissionControlSuiteReceipt.model_validate(
        read_json(tmp_path / "control_suite_receipt.json")
    )
    mismatched = control_suite.model_copy(update={"authority_profile": "canonical"})
    monkeypatch.setattr(
        AdmissionControlSuiteReceipt,
        "model_validate",
        classmethod(lambda _cls, _value: mismatched),
    )

    with pytest.raises(AcquisitionAuditError, match="trust or control authority") as error:
        audit_acquisition(contract, tmp_path)

    assert isinstance(error.value.__cause__, AcquisitionAuditError)
    assert str(error.value.__cause__) == "control suite authority profile differs from the contract"


@pytest.mark.parametrize(
    ("resolves_shortcut", "expected_verdict"),
    [(False, "PASS_PILOT"), (True, "KILL_CONSTRUCT")],
)
def test_v1_admission_report_rejects_canonical_terminal_verdicts(
    tmp_path: Path,
    *,
    resolves_shortcut: bool,
    expected_verdict: str,
) -> None:
    contract = build_acquisition_tree(tmp_path)
    if resolves_shortcut:
        _set_v1_shortcut_resolution(tmp_path)
    report = audit_acquisition(contract, tmp_path)
    assert report.verdict == expected_verdict

    forged = report.model_dump(mode="json")
    forged["authority_profile"] = "canonical"
    with pytest.raises(
        ValidationError,
        match="V1 shortcut reports cannot authorize a canonical verdict",
    ):
        AcquisitionAdmissionReport.model_validate(forged)


def test_v1_shortcut_report_rejects_fake_v2_schema_relabel(tmp_path: Path) -> None:
    build_acquisition_tree(tmp_path)
    relabelled = read_json(tmp_path / "shortcut_baseline.json")
    relabelled["schema_version"] = "fieldtrue.shortcut-baseline-report.v2"

    with pytest.raises(ValidationError) as error:
        ShortcutBaselineReport.model_validate(relabelled)

    assert any(
        item["loc"] == ("schema_version",) and item["type"] == "literal_error"
        for item in error.value.errors()
    )


def test_29_complete_dossiers_are_blocked_not_promoted_by_rows(tmp_path: Path) -> None:
    contract = build_acquisition_tree(tmp_path, count=29)
    report = audit_acquisition(contract, tmp_path)
    record_control_observation(tmp_path, report)

    assert report.verdict == "BLOCKED_ACQUISITION"
    assert len(report.eligible_incident_ids) == 29
    coverage = next(gate for gate in report.gates if gate.gate_id == "conjunctive-coverage")
    assert coverage.status == "blocked"
    assert coverage.observed["checks"]["complete_count"] is False


def test_unknown_required_right_is_a_distinct_block(tmp_path: Path) -> None:
    contract = build_acquisition_tree(
        tmp_path, blocked_permission=PermissionKind.INDEPENDENT_REVIEW
    )
    report = audit_acquisition(contract, tmp_path)

    assert report.verdict == "BLOCKED_RIGHTS"
    assert len(report.eligible_incident_ids) == 30
    rights = next(gate for gate in report.gates if gate.gate_id == "source-rights")
    assert rights.observed["failures"] == ["physical-source:independent_review"]


def test_unknown_derived_redistribution_right_blocks_admission(tmp_path: Path) -> None:
    contract = build_acquisition_tree(
        tmp_path,
        blocked_permission=PermissionKind.REDISTRIBUTE_DERIVED,
    )

    report = audit_acquisition(contract, tmp_path)

    assert report.verdict == "BLOCKED_RIGHTS"
    rights = next(gate for gate in report.gates if gate.gate_id == "source-rights")
    assert rights.observed["failures"] == ["physical-source:redistribute_derived"]


def test_prohibited_derived_redistribution_right_blocks_admission(tmp_path: Path) -> None:
    contract = build_acquisition_tree(
        tmp_path,
        blocked_permission=PermissionKind.REDISTRIBUTE_DERIVED,
        blocked_permission_decision=PermissionDecision.PROHIBITED,
    )

    report = audit_acquisition(contract, tmp_path)

    assert report.verdict == "BLOCKED_RIGHTS"
    rights = next(gate for gate in report.gates if gate.gate_id == "source-rights")
    assert rights.observed["failures"] == ["physical-source:redistribute_derived"]


def test_resource_breach_is_invalid_even_when_corpus_is_complete(tmp_path: Path) -> None:
    contract = build_acquisition_tree(tmp_path)
    usage_path = tmp_path / "resource_usage.json"
    usage = read_json(usage_path)
    usage["gpu_seconds"] = 1
    write_json(usage_path, usage)

    report = audit_acquisition(contract, tmp_path)
    assert report.verdict == "INVALID"
    resource = next(gate for gate in report.gates if gate.gate_id == "resource-ceiling")
    assert resource.status == "invalid"
    assert resource.observed["failures"] == ["gpu_seconds"]


def test_source_byte_tampering_is_invalid(tmp_path: Path) -> None:
    contract = build_acquisition_tree(tmp_path)
    (tmp_path / "common" / "source.bin").write_bytes(b"rewritten\n")

    report = audit_acquisition(contract, tmp_path)
    assert report.verdict == "INVALID"
    assert any(
        "artifact binding mismatch" in failure for failure in report.gates[0].observed["failures"]
    )


def test_semantic_truth_tampering_fails_after_raw_binding_is_updated(tmp_path: Path) -> None:
    contract = build_acquisition_tree(tmp_path)
    dossier_path = tmp_path / "dossiers" / "incident-000.json"

    def mutate(value: dict[str, object]) -> None:
        value["fault_family"] = "rewritten-fault"

    _rewrite_bound_json(tmp_path, dossier_path, "truth_record", mutate)
    report = audit_acquisition(contract, tmp_path)
    assert report.verdict == "INVALID"
    assert any(
        "evidence, truth, and group identity" in failure
        for failure in report.gates[0].observed["failures"]
    )


def test_zero_information_placebo_is_rejected(tmp_path: Path) -> None:
    contract = build_acquisition_tree(tmp_path, zero_information_test=True)
    report = audit_acquisition(contract, tmp_path)

    assert report.verdict == "INVALID"
    assert len(report.eligible_incident_ids) == 0
    assert any(
        "positive-information-gain" in failure for failure in report.gates[0].observed["failures"]
    )


def test_cloned_full_capture_is_rejected_after_valid_resigning(tmp_path: Path) -> None:
    contract = build_acquisition_tree(tmp_path)
    first_provenance = read_json(
        tmp_path / "artifacts" / "incident-000" / "physical-provenance.json"
    )
    dossier_path = tmp_path / "dossiers" / "incident-001.json"

    def clone_capture(value: dict[str, Any]) -> None:
        value["physical_capture"] = deepcopy(first_provenance["physical_capture"])

    _rewrite_signed_bound_json(
        tmp_path,
        dossier_path,
        "physical_provenance",
        PhysicalProvenanceRecord,
        subject_kind=AttestationSubjectKind.PHYSICAL_PROVENANCE,
        signer_role=RoleKind.SOURCE_STEWARD,
        issued_at_field="acquired_at",
        mutate=clone_capture,
    )

    report = audit_acquisition(contract, tmp_path)
    record_control_observation(tmp_path, report)
    assert report.verdict == "INVALID"
    assert "physical roots reuse identical full-capture bytes" in _integrity_failures(report)


def test_identity_normalized_near_duplicate_physical_captures_are_invalid(
    tmp_path: Path,
) -> None:
    contract = build_acquisition_tree(tmp_path)
    capture_hashes: list[str] = []
    for incident_id in ("incident-000", "incident-001"):
        dossier_path = tmp_path / "dossiers" / f"{incident_id}.json"
        dossier = read_json(dossier_path)
        payload = _identity_payload(dossier, "physical-capture", 16)

        def replace_capture(value: dict[str, Any], *, content: bytes = payload) -> None:
            _replace_bound_bytes(tmp_path, value["physical_capture"], content)
            capture_hashes.append(value["physical_capture"]["sha256"])

        _rewrite_signed_bound_json(
            tmp_path,
            dossier_path,
            "physical_provenance",
            PhysicalProvenanceRecord,
            subject_kind=AttestationSubjectKind.PHYSICAL_PROVENANCE,
            signer_role=RoleKind.SOURCE_STEWARD,
            issued_at_field="acquired_at",
            mutate=replace_capture,
        )

    report = audit_acquisition(contract, tmp_path)
    assert report.verdict == "INVALID"
    assert len(set(capture_hashes)) == 2
    assert any(
        "near-duplicate-physical-capture:" in failure for failure in _integrity_failures(report)
    )
    assert "physical roots reuse identical full-capture bytes" not in _integrity_failures(report)


def test_shared_independence_group_is_rejected_after_provenance_resigning(
    tmp_path: Path,
) -> None:
    contract = build_acquisition_tree(tmp_path)
    first = read_json(tmp_path / "dossiers" / "incident-000.json")
    dossier_path = tmp_path / "dossiers" / "incident-001.json"
    dossier = read_json(dossier_path)
    shared_group = first["group"]["independence_group_id"]
    dossier["group"]["independence_group_id"] = shared_group
    write_json(dossier_path, dossier)

    _rewrite_signed_bound_json(
        tmp_path,
        dossier_path,
        "physical_provenance",
        PhysicalProvenanceRecord,
        subject_kind=AttestationSubjectKind.PHYSICAL_PROVENANCE,
        signer_role=RoleKind.SOURCE_STEWARD,
        issued_at_field="acquired_at",
        mutate=lambda value: value.update({"independence_group_id": shared_group}),
    )
    _refresh_model_visible_leakage_scan(tmp_path, dossier_path)

    report = audit_acquisition(contract, tmp_path)
    assert report.verdict == "INVALID"
    assert "physical roots reuse an independence group" in _integrity_failures(report)


def test_one_session_cannot_claim_multiple_physical_groups(tmp_path: Path) -> None:
    contract = build_acquisition_tree(tmp_path)
    first = read_json(tmp_path / "dossiers" / "incident-000.json")
    dossier_path = tmp_path / "dossiers" / "incident-001.json"
    dossier = read_json(dossier_path)
    shared_session = first["group"]["acquisition_session_id"]
    dossier["group"]["acquisition_session_id"] = shared_session
    write_json(dossier_path, dossier)

    _rewrite_signed_bound_json(
        tmp_path,
        dossier_path,
        "physical_provenance",
        PhysicalProvenanceRecord,
        subject_kind=AttestationSubjectKind.PHYSICAL_PROVENANCE,
        signer_role=RoleKind.SOURCE_STEWARD,
        issued_at_field="acquired_at",
        mutate=lambda value: value.update({"acquisition_session_id": shared_session}),
    )
    _refresh_model_visible_leakage_scan(tmp_path, dossier_path)

    report = audit_acquisition(contract, tmp_path)
    assert report.verdict == "INVALID"
    assert "one acquisition session claims multiple independence groups" in _integrity_failures(
        report
    )


def test_one_modality_case_is_invalid(tmp_path: Path) -> None:
    contract = build_acquisition_tree(tmp_path)
    dossier_path = tmp_path / "dossiers" / "incident-000.json"

    def collapse_modalities(evidence: dict[str, Any]) -> None:
        evidence["evidence"][1]["modality"] = evidence["evidence"][0]["modality"]

    _rewrite_evidence_bundle_and_projection(tmp_path, dossier_path, collapse_modalities)
    report = audit_acquisition(contract, tmp_path)
    record_control_observation(tmp_path, report)

    assert report.verdict == "INVALID"
    assert any("one-modality:" in failure for failure in _integrity_failures(report))


def test_duplicated_modality_content_is_rejected_by_projection_contract(tmp_path: Path) -> None:
    contract = build_acquisition_tree(tmp_path)
    dossier_path = tmp_path / "dossiers" / "incident-000.json"

    def duplicate_evidence(value: dict[str, Any]) -> None:
        value["evidence"][1]["artifact"] = deepcopy(value["evidence"][0]["artifact"])

    def duplicate_projection(value: dict[str, Any]) -> None:
        value["model_input_artifacts"][1] = deepcopy(value["model_input_artifacts"][0])

    _rewrite_bound_json(tmp_path, dossier_path, "evidence_bundle", duplicate_evidence)
    _rewrite_bound_json(
        tmp_path,
        dossier_path,
        "model_visible_projection",
        duplicate_projection,
    )

    report = audit_acquisition(contract, tmp_path)
    record_control_observation(tmp_path, report)
    assert report.verdict == "INVALID"
    assert any("invalid ModelVisibleProjection" in item for item in _integrity_failures(report))


def test_stationary_image_proxy_is_invalid(tmp_path: Path) -> None:
    contract = build_acquisition_tree(tmp_path)
    dossier_path = tmp_path / "dossiers" / "incident-000.json"

    def replace_operational_streams_with_static_artifacts(evidence: dict[str, Any]) -> None:
        evidence["evidence"][0]["modality"] = "image"
        evidence["evidence"][1]["modality"] = "configuration"

    _rewrite_evidence_bundle_and_projection(
        tmp_path,
        dossier_path,
        replace_operational_streams_with_static_artifacts,
    )
    report = audit_acquisition(contract, tmp_path)
    record_control_observation(tmp_path, report)

    assert report.verdict == "INVALID"
    assert any("stationary-image-proxy:" in failure for failure in _integrity_failures(report))


def test_shuffled_modality_order_is_invalid(tmp_path: Path) -> None:
    contract = build_acquisition_tree(tmp_path)
    dossier_path = tmp_path / "dossiers" / "incident-000.json"

    def reverse_source_stream_order(evidence: dict[str, Any]) -> None:
        evidence["evidence"].reverse()

    _rewrite_evidence_bundle_and_projection(tmp_path, dossier_path, reverse_source_stream_order)
    report = audit_acquisition(contract, tmp_path)
    record_control_observation(tmp_path, report)

    assert report.verdict == "INVALID"
    assert any("shuffled-modality:" in failure for failure in _integrity_failures(report))


def test_identity_normalized_near_duplicate_model_streams_are_invalid(tmp_path: Path) -> None:
    contract = build_acquisition_tree(tmp_path)
    for incident_id in ("incident-000", "incident-001"):
        _replace_model_streams_with_identity_normalized_content(
            tmp_path,
            tmp_path / "dossiers" / f"{incident_id}.json",
        )
    _refresh_split_locks(tmp_path)

    report = audit_acquisition(contract, tmp_path)
    assert report.verdict == "INVALID"
    assert any(
        "near-duplicate-model-visible:" in failure for failure in _integrity_failures(report)
    )


def test_settled_outcome_bytes_cannot_enter_model_visible_evidence(tmp_path: Path) -> None:
    contract = build_acquisition_tree(tmp_path)
    dossier_path = tmp_path / "dossiers" / "incident-000.json"
    dossier = read_json(dossier_path)
    settled = read_json(tmp_path / dossier["settled_outcome"]["path"])
    settled_binding = settled["outcome_artifacts"][0]
    settled_relative = settled_binding.get("path", settled_binding.get("uri"))
    assert isinstance(settled_relative, str)
    settled_payload = (tmp_path / settled_relative).read_bytes()

    evidence_path = tmp_path / dossier["evidence_bundle"]["path"]
    evidence = read_json(evidence_path)
    _replace_bound_bytes(tmp_path, evidence["evidence"][1]["artifact"], settled_payload)
    write_json(evidence_path, evidence)
    dossier["evidence_bundle"]["sha256"] = sha256_file(evidence_path)
    dossier["evidence_bundle"]["bytes"] = evidence_path.stat().st_size
    _resign_evidence_sequence(tmp_path, dossier, evidence)

    def replace_projection_stream(value: dict[str, Any]) -> None:
        replaced = evidence["evidence"][1]["artifact"]
        value["model_input_artifacts"][1]["sha256"] = replaced["sha256"]
        value["model_input_artifacts"][1]["bytes"] = replaced["bytes"]
        value["evidence_bundle_sha256"] = sha256_value(evidence)

    write_json(dossier_path, dossier)
    _rewrite_signed_bound_json(
        tmp_path,
        dossier_path,
        "model_visible_projection",
        ModelVisibleProjection,
        subject_kind=AttestationSubjectKind.MODEL_VISIBLE_PROJECTION,
        signer_role=RoleKind.EVIDENCE_CURATOR,
        issued_at_field="projected_at",
        mutate=replace_projection_stream,
    )
    _refresh_model_visible_leakage_scan(tmp_path, dossier_path)

    report = audit_acquisition(contract, tmp_path)
    assert report.verdict == "INVALID"
    assert any(
        "model-visible-content-collision:" in failure for failure in _integrity_failures(report)
    )


def test_curator_clean_claim_cannot_hide_forbidden_model_input_bytes(tmp_path: Path) -> None:
    contract = build_acquisition_tree(tmp_path)
    dossier_path = tmp_path / "dossiers" / "incident-000.json"
    dossier = read_json(dossier_path)
    evidence_path = tmp_path / dossier["evidence_bundle"]["path"]
    evidence = read_json(evidence_path)
    leaked_payload = b'{"site":"site-0","samples_hex":"' + (b"ab" * 600) + b'"}\n'
    _replace_bound_bytes(tmp_path, evidence["evidence"][0]["artifact"], leaked_payload)
    write_json(evidence_path, evidence)
    dossier["evidence_bundle"]["sha256"] = sha256_file(evidence_path)
    dossier["evidence_bundle"]["bytes"] = evidence_path.stat().st_size
    _resign_evidence_sequence(tmp_path, dossier, evidence)

    projection_path = tmp_path / dossier["model_visible_projection"]["path"]
    projection = read_json(projection_path)
    projection.pop("attestation")
    changed = evidence["evidence"][0]["artifact"]
    projection["model_input_artifacts"][0]["sha256"] = changed["sha256"]
    projection["model_input_artifacts"][0]["bytes"] = changed["bytes"]
    projection["evidence_bundle_sha256"] = sha256_value(evidence)

    scan_path = tmp_path / projection["leakage_scan"]["path"]
    forged_scan = read_json(scan_path)
    forged_scan["input_artifacts_sha256"] = sha256_value(tuple(projection["model_input_artifacts"]))
    forged_scan["artifact_scans"][0]["artifact_sha256"] = changed["sha256"]
    forged_scan["artifact_scans"][0]["artifact_bytes"] = changed["bytes"]
    forged_scan["artifact_scans"][0]["forbidden_field_paths"] = []
    forged_scan["artifact_scans"][0]["matched_identity_token_sha256"] = []
    forged_scan["leakage_detected"] = False
    write_json(scan_path, ModelVisibleLeakageScanReport.model_validate(forged_scan))
    projection["leakage_scan"]["sha256"] = sha256_file(scan_path)
    projection["leakage_scan"]["bytes"] = scan_path.stat().st_size

    resigned = _signed_model(
        ModelVisibleProjection,
        projection,
        subject_kind=AttestationSubjectKind.MODEL_VISIBLE_PROJECTION,
        signing_key=ACTOR_KEYS[RoleKind.EVIDENCE_CURATOR],
        signer_id=f"actor-{RoleKind.EVIDENCE_CURATOR.value}",
        attestation_id="forged-clean-leakage-scan",
        issued_at=_aware(projection["projected_at"]),
    )
    write_json(projection_path, resigned)
    dossier["model_visible_projection"]["sha256"] = sha256_file(projection_path)
    dossier["model_visible_projection"]["bytes"] = projection_path.stat().st_size
    write_json(dossier_path, dossier)
    _refresh_split_locks(tmp_path)

    report = audit_acquisition(contract, tmp_path)
    assert report.verdict == "INVALID"
    assert any(
        "model-visible projection is incomplete or leaks metadata" in failure
        for failure in _integrity_failures(report)
    )


def test_recommendation_only_diagnostic_without_distinct_realization_is_rejected(
    tmp_path: Path,
) -> None:
    contract = build_acquisition_tree(tmp_path)
    dossier_path = tmp_path / "dossiers" / "incident-000.json"

    _rewrite_signed_bound_json(
        tmp_path,
        dossier_path,
        "diagnostic_execution",
        DiagnosticExecution,
        subject_kind=AttestationSubjectKind.DIAGNOSTIC_EXECUTION,
        signer_role=RoleKind.TEST_EXECUTOR,
        issued_at_field="finished_at",
        mutate=lambda value: value.update({"realized_action": deepcopy(value["command"])}),
    )

    report = audit_acquisition(contract, tmp_path)
    record_control_observation(tmp_path, report)
    assert report.verdict == "INVALID"
    assert any("diagnostic-realization:" in item for item in _integrity_failures(report))


def test_resigned_diagnostic_changes_without_matching_safety_approval_are_invalid(
    tmp_path: Path,
) -> None:
    contract = build_acquisition_tree(tmp_path)
    dossier_path = tmp_path / "dossiers" / "incident-000.json"

    def change_approved_action(value: dict[str, Any]) -> None:
        _replace_bound_bytes(
            tmp_path,
            value["command"],
            b'{"incident":"incident-000","command":"unapproved-pulse"}\n',
        )
        _replace_bound_bytes(
            tmp_path,
            value["realized_action"],
            b'{"incident":"incident-000","realized":"unapproved-pulse"}\n',
        )

    _rewrite_signed_bound_json(
        tmp_path,
        dossier_path,
        "diagnostic_execution",
        DiagnosticExecution,
        subject_kind=AttestationSubjectKind.DIAGNOSTIC_EXECUTION,
        signer_role=RoleKind.TEST_EXECUTOR,
        issued_at_field="finished_at",
        mutate=change_approved_action,
    )
    report = audit_acquisition(contract, tmp_path)

    assert report.verdict == "INVALID"
    assert any(
        "diagnostic-action-conformance:" in failure for failure in _integrity_failures(report)
    )


def test_outcome_verifier_independence_overlap_is_rejected(tmp_path: Path) -> None:
    contract = build_acquisition_tree(tmp_path)
    registry_path = tmp_path / "trust_registry.json"
    registry = read_json(registry_path)
    overlap_group = f"group-{RoleKind.TEST_EXECUTOR.value}"
    for actor in registry["actors"]:
        if actor["actor_id"] == f"actor-{RoleKind.OUTCOME_VERIFIER.value}":
            actor["independence_group_id"] = overlap_group
    actors = tuple(TrustedActor.model_validate(actor) for actor in registry["actors"])
    resigned_registry = issue_actor_trust_registry(
        ANCHOR_KEY,
        registry_id=registry["registry_id"],
        issued_at=_aware(registry["issued_at"]),
        actors=actors,
    )
    write_json(registry_path, resigned_registry)

    dossier_path = tmp_path / "dossiers" / "incident-000.json"
    dossier = read_json(dossier_path)
    for role in dossier["roles"]:
        if role["role"] == RoleKind.OUTCOME_VERIFIER.value:
            role["independence_group_id"] = overlap_group
    write_json(dossier_path, dossier)
    _rewrite_signed_bound_json(
        tmp_path,
        dossier_path,
        "settled_outcome",
        SettledOutcomeRecord,
        subject_kind=AttestationSubjectKind.SETTLED_OUTCOME,
        signer_role=RoleKind.OUTCOME_VERIFIER,
        issued_at_field="attestation.issued_at",
        mutate=lambda value: value.update({"outcome_authority_independence_group": overlap_group}),
    )

    dossier = read_json(dossier_path)
    settled_binding = dossier["settled_outcome"]
    settled = SettledOutcomeRecord.model_validate(read_json(tmp_path / settled_binding["path"]))
    for index, review in enumerate(dossier["reviews"]):
        if review["purpose"] != "settled_outcome":
            continue
        review_body = deepcopy(review)
        review_body.pop("attestation")
        review_body["subject_sha256"] = sha256_value(settled)
        signed_review = _signed_model(
            BoundReview,
            review_body,
            subject_kind=AttestationSubjectKind.REVIEW,
            signing_key=ACTOR_KEYS[RoleKind.OUTCOME_VERIFIER],
            signer_id=f"actor-{RoleKind.OUTCOME_VERIFIER.value}",
            attestation_id="negative-control-outcome-review",
            issued_at=_aware(review_body["reviewed_at"]),
        )
        dossier["reviews"][index] = signed_review.model_dump(mode="json")
    write_json(dossier_path, dossier)

    report = audit_acquisition(contract, tmp_path)
    record_control_observation(tmp_path, report)
    assert report.verdict == "INVALID"
    assert any(
        "forbidden role independence overlap" in item for item in _integrity_failures(report)
    )


def test_evidence_curator_cannot_share_truth_producer_independence_group(
    tmp_path: Path,
) -> None:
    contract = build_acquisition_tree(tmp_path)
    registry_path = tmp_path / "trust_registry.json"
    registry = read_json(registry_path)
    truth_group = next(
        actor["independence_group_id"]
        for actor in registry["actors"]
        if actor["actor_id"] == f"actor-{RoleKind.TRUTH_PRODUCER.value}"
    )
    for actor in registry["actors"]:
        if actor["actor_id"] == f"actor-{RoleKind.EVIDENCE_CURATOR.value}":
            actor["independence_group_id"] = truth_group
    actors = tuple(TrustedActor.model_validate(actor) for actor in registry["actors"])
    write_json(
        registry_path,
        issue_actor_trust_registry(
            ANCHOR_KEY,
            registry_id=registry["registry_id"],
            issued_at=_aware(registry["issued_at"]),
            actors=actors,
        ),
    )
    for dossier_path in sorted((tmp_path / "dossiers").glob("*.json")):
        dossier = read_json(dossier_path)
        assignment = next(
            role for role in dossier["roles"] if role["role"] == RoleKind.EVIDENCE_CURATOR.value
        )
        assignment["independence_group_id"] = truth_group
        write_json(dossier_path, dossier)

    report = audit_acquisition(contract, tmp_path)
    assert report.verdict == "INVALID"
    assert any(
        "forbidden role independence overlap" in failure for failure in _integrity_failures(report)
    )


def test_forged_selected_planner_fields_are_recomputed_and_rejected(tmp_path: Path) -> None:
    contract = build_acquisition_tree(tmp_path)
    dossier_path = tmp_path / "dossiers" / "incident-000.json"

    def forge_selection(value: dict[str, Any]) -> None:
        value["planner_id"] = "forged-planner"
        value["utility"] += 1

    _rewrite_bound_json(tmp_path, dossier_path, "selected_test", forge_selection)
    report = audit_acquisition(contract, tmp_path)
    assert report.verdict == "INVALID"
    assert any(
        "selected test fields differ from deterministic recomputation" in item
        for item in _integrity_failures(report)
    )


def test_unsigned_trust_registry_is_rejected_before_dossier_admission(tmp_path: Path) -> None:
    contract = build_acquisition_tree(tmp_path)
    path = tmp_path / "trust_registry.json"
    registry = read_json(path)
    registry["signature"] = "0" * 128
    write_json(path, registry)

    with pytest.raises(AcquisitionAuditError, match="trust or control authority is invalid"):
        audit_acquisition(contract, tmp_path)


def test_validly_resigned_trust_registry_cannot_postdate_governed_activity(
    tmp_path: Path,
) -> None:
    contract = build_acquisition_tree(tmp_path)
    registry_path = tmp_path / "trust_registry.json"
    registry = read_json(registry_path)
    actors = tuple(TrustedActor.model_validate(actor) for actor in registry["actors"])
    write_json(
        registry_path,
        issue_actor_trust_registry(
            ANCHOR_KEY,
            registry_id=registry["registry_id"],
            issued_at=BASE + timedelta(days=1),
            actors=actors,
        ),
    )

    with pytest.raises(AcquisitionAuditError, match="trust or control authority is invalid"):
        audit_acquisition(contract, tmp_path)


def test_validly_resigned_protocol_reviews_cannot_postdate_physical_execution(
    tmp_path: Path,
) -> None:
    contract = build_acquisition_tree(tmp_path)
    protocol_path = tmp_path / "protocol_reviews.json"
    protocol = read_json(protocol_path)
    reviewer_roles = {
        "aerospace": RoleKind.MECHANISM_REVIEWER,
        "robotics": RoleKind.SAFETY_REVIEWER,
    }
    reviewed_at = BASE + timedelta(minutes=60)
    records: list[ProtocolReviewRecord] = []
    for review in protocol["reviews"]:
        body = {key: value for key, value in review.items() if key != "attestation"}
        body["reviewed_at"] = reviewed_at
        role = reviewer_roles[body["domain"]]
        records.append(
            _signed_model(
                ProtocolReviewRecord,
                body,
                subject_kind=AttestationSubjectKind.PROTOCOL_REVIEW,
                signing_key=ACTOR_KEYS[role],
                signer_id=body["reviewer_id"],
                attestation_id=f"negative-control-{body['domain']}-late-protocol-review",
                issued_at=reviewed_at,
            )
        )
    write_json(protocol_path, ProtocolReviewRegistry(reviews=tuple(records)))

    report = audit_acquisition(contract, tmp_path)

    assert report.verdict == "INVALID"
    assert any(
        "protocol review does not precede physical test execution" in failure
        for failure in _integrity_failures(report)
    )


def test_validly_signed_projection_cannot_claim_pre_acquisition_authority(
    tmp_path: Path,
) -> None:
    contract = build_acquisition_tree(tmp_path)
    dossier_path = tmp_path / "dossiers" / "incident-000.json"
    _rewrite_signed_bound_json(
        tmp_path,
        dossier_path,
        "model_visible_projection",
        ModelVisibleProjection,
        subject_kind=AttestationSubjectKind.MODEL_VISIBLE_PROJECTION,
        signer_role=RoleKind.EVIDENCE_CURATOR,
        issued_at_field="projected_at",
        mutate=lambda value: value.update(
            {"projected_at": (BASE - timedelta(minutes=1)).isoformat()}
        ),
    )

    report = audit_acquisition(contract, tmp_path)

    assert report.verdict == "INVALID"
    assert any(
        "model-visible projection is incomplete" in failure
        for failure in _integrity_failures(report)
    )


def test_per_axis_split_leakage_is_rejected_with_structural_counts_intact(
    tmp_path: Path,
) -> None:
    contract = build_acquisition_tree(tmp_path)
    registry_path = tmp_path / "split_locks.json"
    registry = read_json(registry_path)
    binding = registry["hardware_family"]
    lock_path = tmp_path / binding["path"]
    lock = read_json(lock_path)
    assignment = next(item for item in lock["assignments"] if item["incident_id"] == "incident-000")
    old_split = assignment["split"]
    new_split = next(name for name in ("train", "validation", "test") if name != old_split)
    assignment["split"] = new_split
    lock["split_counts"][old_split] -= 1
    lock["split_counts"][new_split] += 1
    write_json(lock_path, lock)
    binding["sha256"] = sha256_file(lock_path)
    binding["bytes"] = lock_path.stat().st_size
    write_json(registry_path, registry)

    report = audit_acquisition(contract, tmp_path)
    assert report.verdict == "INVALID"
    assert any("leakage component" in item for item in _integrity_failures(report))


def test_commercial_research_right_unknown_is_a_distinct_block(tmp_path: Path) -> None:
    contract = build_acquisition_tree(
        tmp_path,
        blocked_permission=PermissionKind.COMMERCIAL_RESEARCH,
    )
    report = audit_acquisition(contract, tmp_path)
    record_control_observation(tmp_path, report)

    assert report.verdict == "BLOCKED_RIGHTS"
    rights = next(gate for gate in report.gates if gate.gate_id == "source-rights")
    assert rights.observed["failures"] == ["physical-source:commercial_research"]


def test_simulated_event_cannot_enter_physical_admission(tmp_path: Path) -> None:
    contract = build_acquisition_tree(tmp_path)
    dossier_path = tmp_path / "dossiers" / "incident-000.json"
    dossier = read_json(dossier_path)
    dossier["group"]["physicality"] = "simulated"
    write_json(dossier_path, dossier)

    report = audit_acquisition(contract, tmp_path)
    record_control_observation(tmp_path, report)
    assert report.verdict == "INVALID"
    assert any(
        "not one claim-bearing physical root event" in item for item in _integrity_failures(report)
    )


def test_truth_metadata_in_model_visible_plane_is_invalid(tmp_path: Path) -> None:
    contract = build_acquisition_tree(tmp_path)
    plane_path = tmp_path / "common" / "plane-separation.json"
    plane = read_json(plane_path)
    fault_assignment = next(
        item for item in plane["assignments"] if item["field_name"] == "fault_label"
    )
    fault_assignment["plane"] = "model_visible"
    write_json(plane_path, plane)
    for dossier_path in (tmp_path / "dossiers").glob("*.json"):
        dossier = read_json(dossier_path)
        binding = dossier["plane_separation_receipt"]
        binding["sha256"] = sha256_file(plane_path)
        binding["bytes"] = plane_path.stat().st_size
        write_json(dossier_path, dossier)

    report = audit_acquisition(contract, tmp_path)
    record_control_observation(tmp_path, report)
    assert report.verdict == "INVALID"
    assert any("forbidden fields are model-visible" in item for item in _integrity_failures(report))


def test_unbounded_clock_transform_is_invalid(tmp_path: Path) -> None:
    contract = build_acquisition_tree(tmp_path)
    dossier_path = tmp_path / "dossiers" / "incident-000.json"
    dossier = read_json(dossier_path)
    dossier["clocks"][0]["offset_ns"] = 100_000_001
    dossier["clocks"][0]["max_alignment_error_ns"] = 100_000_001
    write_json(dossier_path, dossier)

    report = audit_acquisition(contract, tmp_path)
    record_control_observation(tmp_path, report)
    assert report.verdict == "INVALID"
    assert any(
        "clock alignment or missingness exceeds the contract" in item
        for item in _integrity_failures(report)
    )


def test_truth_custody_opened_before_commitments_is_invalid(tmp_path: Path) -> None:
    contract = build_acquisition_tree(tmp_path)
    dossier_path = tmp_path / "dossiers" / "incident-000.json"
    premature_unseal = (BASE + timedelta(minutes=35)).isoformat().replace("+00:00", "Z")
    _rewrite_signed_bound_json(
        tmp_path,
        dossier_path,
        "truth_custody",
        TruthCustodyReceipt,
        subject_kind=AttestationSubjectKind.TRUTH_CUSTODY,
        signer_role=RoleKind.MECHANISM_REVIEWER,
        issued_at_field="unsealed_at",
        mutate=lambda value: value.update({"unsealed_at": premature_unseal}),
    )

    report = audit_acquisition(contract, tmp_path)
    record_control_observation(tmp_path, report)
    assert report.verdict == "INVALID"
    assert any(
        "truth custody is incomplete or chronology differs" in item
        for item in _integrity_failures(report)
    )


def test_validly_resigned_post_outcome_ambiguity_review_is_invalid(tmp_path: Path) -> None:
    contract = build_acquisition_tree(tmp_path)
    dossier_path = tmp_path / "dossiers" / "incident-000.json"
    dossier = read_json(dossier_path)
    reviewed_at = BASE + timedelta(minutes=94)
    for index, review in enumerate(dossier["reviews"]):
        if review["purpose"] != ReviewPurpose.AMBIGUITY.value:
            continue
        review_body = deepcopy(review)
        review_body.pop("attestation")
        review_body["reviewed_at"] = reviewed_at
        signed_review = _signed_model(
            BoundReview,
            review_body,
            subject_kind=AttestationSubjectKind.REVIEW,
            signing_key=ACTOR_KEYS[RoleKind.MECHANISM_REVIEWER],
            signer_id=f"actor-{RoleKind.MECHANISM_REVIEWER.value}",
            attestation_id="negative-control-post-outcome-ambiguity-review",
            issued_at=reviewed_at,
        )
        dossier["reviews"][index] = signed_review.model_dump(mode="json")
        break
    write_json(dossier_path, dossier)

    report = audit_acquisition(contract, tmp_path)

    assert report.verdict == "INVALID"
    assert any(
        "review and execution times do not match the frozen timeline" in item
        for item in _integrity_failures(report)
    )


def test_known_only_hypothesis_set_is_invalid(tmp_path: Path) -> None:
    contract = build_acquisition_tree(tmp_path)
    dossier_path = tmp_path / "dossiers" / "incident-000.json"

    def remove_open_world_hypothesis(value: dict[str, Any]) -> None:
        for hypothesis in value["hypotheses"]:
            hypothesis["unknown"] = False

    _rewrite_bound_json(
        tmp_path,
        dossier_path,
        "hypothesis_set",
        remove_open_world_hypothesis,
    )
    report = audit_acquisition(contract, tmp_path)
    record_control_observation(tmp_path, report)
    assert report.verdict == "INVALID"
    assert any("invalid HypothesisSet" in item for item in _integrity_failures(report))


def test_asserted_recovery_without_distinct_realization_is_invalid(tmp_path: Path) -> None:
    contract = build_acquisition_tree(tmp_path)
    dossier_path = tmp_path / "dossiers" / "incident-000.json"
    _rewrite_signed_bound_json(
        tmp_path,
        dossier_path,
        "recovery_execution",
        RecoveryExecution,
        subject_kind=AttestationSubjectKind.RECOVERY_EXECUTION,
        signer_role=RoleKind.RECOVERY_EXECUTOR,
        issued_at_field="finished_at",
        mutate=lambda value: value.update({"realized_action": deepcopy(value["commanded_action"])}),
    )

    report = audit_acquisition(contract, tmp_path)
    record_control_observation(tmp_path, report)
    assert report.verdict == "INVALID"
    assert any(
        "recovery and settled outcome are not cross-bound" in item
        for item in _integrity_failures(report)
    )


def test_validly_resigned_settled_outcome_cannot_swap_diagnostic_chain(
    tmp_path: Path,
) -> None:
    contract = build_acquisition_tree(tmp_path)
    dossier_path = tmp_path / "dossiers" / "incident-000.json"
    other_dossier = read_json(tmp_path / "dossiers" / "incident-001.json")
    swapped_hashes = {
        "selected_test_sha256": other_dossier["selected_test"]["sha256"],
        "test_observation_sha256": other_dossier["test_observation"]["sha256"],
        "diagnostic_execution_sha256": other_dossier["diagnostic_execution"]["sha256"],
    }
    _rewrite_signed_bound_json(
        tmp_path,
        dossier_path,
        "settled_outcome",
        SettledOutcomeRecord,
        subject_kind=AttestationSubjectKind.SETTLED_OUTCOME,
        signer_role=RoleKind.OUTCOME_VERIFIER,
        issued_at_field="attestation.issued_at",
        mutate=lambda value: value.update(swapped_hashes),
    )

    dossier = read_json(dossier_path)
    settled = SettledOutcomeRecord.model_validate(
        read_json(tmp_path / dossier["settled_outcome"]["path"])
    )
    for index, review in enumerate(dossier["reviews"]):
        if review["purpose"] != ReviewPurpose.SETTLED_OUTCOME.value:
            continue
        review_body = deepcopy(review)
        review_body.pop("attestation")
        review_body["subject_sha256"] = sha256_value(settled)
        signed_review = _signed_model(
            BoundReview,
            review_body,
            subject_kind=AttestationSubjectKind.REVIEW,
            signing_key=ACTOR_KEYS[RoleKind.OUTCOME_VERIFIER],
            signer_id=f"actor-{RoleKind.OUTCOME_VERIFIER.value}",
            attestation_id="negative-control-swapped-diagnostic-chain-review",
            issued_at=_aware(review_body["reviewed_at"]),
        )
        dossier["reviews"][index] = signed_review.model_dump(mode="json")
        break
    write_json(dossier_path, dossier)

    report = audit_acquisition(contract, tmp_path)

    assert report.verdict == "INVALID"
    assert any(
        "recovery and settled outcome are not cross-bound" in item
        for item in _integrity_failures(report)
    )


def test_resolving_shortcut_kills_the_construct(tmp_path: Path) -> None:
    contract = build_acquisition_tree(tmp_path)
    _set_v1_shortcut_resolution(tmp_path)

    report = audit_acquisition(contract, tmp_path)
    record_control_observation(tmp_path, report)
    assert report.authority_profile == "test_fixture"
    assert report.verdict == "KILL_CONSTRUCT"
    shortcut = next(gate for gate in report.gates if gate.gate_id == "shortcut-baseline")
    assert shortcut.observed["resolving_rules"] == ["source-identity"]


def _assert_comparator_omission_is_invalid(root: Path, kind: str) -> None:
    contract = build_acquisition_tree(root)
    registry = read_json(root / "intervention_comparators.json")
    comparator = next(item for item in registry["comparators"] if item["kind"] == kind)
    (root / comparator["implementation"]["path"]).unlink()

    report = audit_acquisition(contract, root)
    record_control_observation(root, report)
    assert report.verdict == "INVALID"
    assert any(
        f"comparators/{kind}/implementation.txt" in item for item in _integrity_failures(report)
    )


def test_no_op_comparator_omission_is_invalid(tmp_path: Path) -> None:
    _assert_comparator_omission_is_invalid(tmp_path, "no_op")


def test_random_safe_comparator_omission_is_invalid(tmp_path: Path) -> None:
    _assert_comparator_omission_is_invalid(tmp_path, "random_safe")


def test_cheapest_safe_comparator_omission_is_invalid(tmp_path: Path) -> None:
    _assert_comparator_omission_is_invalid(tmp_path, "cheapest_safe")


def test_wrong_safe_comparator_omission_is_invalid(tmp_path: Path) -> None:
    _assert_comparator_omission_is_invalid(tmp_path, "wrong_safe")


def test_role_group_alias_does_not_create_independence(tmp_path: Path) -> None:
    contract = build_acquisition_tree(tmp_path)
    dossier_path = tmp_path / "dossiers" / "incident-000.json"
    dossier = read_json(dossier_path)
    roles = {item["role"]: item for item in dossier["roles"]}
    roles["safety_reviewer"]["independence_group_id"] = roles["test_proposer"][
        "independence_group_id"
    ]
    write_json(dossier_path, dossier)

    report = audit_acquisition(contract, tmp_path)
    assert report.verdict == "INVALID"
    assert any("trust-registry bound" in failure for failure in _integrity_failures(report))


def test_clock_bound_and_model_visible_cutoff_fail_closed(tmp_path: Path) -> None:
    contract = build_acquisition_tree(tmp_path)
    dossier_path = tmp_path / "dossiers" / "incident-000.json"
    dossier = read_json(dossier_path)
    dossier["clocks"][0]["max_alignment_error_ns"] = 100_000_001
    write_json(dossier_path, dossier)

    report = audit_acquisition(contract, tmp_path)
    assert report.verdict == "INVALID"
    assert any("clock alignment" in failure for failure in report.gates[0].observed["failures"])

    dossier = read_json(dossier_path)
    dossier["clocks"][0]["max_alignment_error_ns"] = 0
    dossier["evidence_times"][0]["normalized_end_ns"] = 1_000_000_001
    write_json(dossier_path, dossier)
    report = audit_acquisition(contract, tmp_path)
    assert any(
        "model-visible cutoff" in failure for failure in report.gates[0].observed["failures"]
    )


def test_forged_test_approval_is_invalid(tmp_path: Path) -> None:
    contract = build_acquisition_tree(tmp_path)
    dossier_path = tmp_path / "dossiers" / "incident-000.json"

    def mutate(value: dict[str, object]) -> None:
        value["signature"] = "0" * 128

    _rewrite_bound_json(tmp_path, dossier_path, "test_approval", mutate)
    report = audit_acquisition(contract, tmp_path)
    record_control_observation(tmp_path, report)

    assert report.verdict == "INVALID"
    assert any("forged-approval:" in failure for failure in _integrity_failures(report))


def test_missing_input_surface_and_duplicate_registries_fail(tmp_path: Path) -> None:
    with pytest.raises(AcquisitionAuditError, match="lacks a required"):
        audit_acquisition(acquisition_contract(), tmp_path)

    contract = build_acquisition_tree(tmp_path)
    source = (tmp_path / "sources" / "physical-source.json").read_bytes()
    (tmp_path / "sources" / "duplicate.json").write_bytes(source)
    with pytest.raises(AcquisitionAuditError, match="source IDs"):
        audit_acquisition(contract, tmp_path)


def test_path_and_low_level_time_contracts_reject_ambiguous_values() -> None:
    with pytest.raises(ValidationError, match="normalized and relative"):
        ArtifactBinding(
            path="../truth.json",
            sha256="a" * 64,
            bytes=1,
            media_type="application/json",
        )
    with pytest.raises(ValidationError, match="ends before"):
        EvidenceTimeBinding(
            evidence_id="evidence-1",
            clock_domain="clock-1",
            normalized_start_ns=2,
            normalized_end_ns=1,
        )
    with pytest.raises(ValidationError, match="truth cannot be unsealed"):
        IncidentTimeline(
            source_acquired_at=BASE,
            truth_committed_at=BASE,
            evidence_cutoff_at=BASE,
            model_visible_cutoff_ns=0,
            hypothesis_committed_at=BASE,
            safe_test_reviewed_at=BASE,
            test_started_at=BASE,
            test_finished_at=BASE,
            recovery_plan_committed_at=BASE,
            recovery_started_at=BASE,
            recovery_finished_at=BASE,
            settled_window_started_at=BASE,
            settled_window_finished_at=BASE + timedelta(seconds=2),
            outcome_verified_at=BASE + timedelta(seconds=2),
            truth_unsealed_at=BASE + timedelta(seconds=1),
        )


def test_plane_source_and_resource_models_are_fail_closed(tmp_path: Path) -> None:
    binding = ArtifactBinding(
        path="artifact.json", sha256="a" * 64, bytes=1, media_type="application/json"
    )
    with pytest.raises(ValidationError, match="exactly one plane"):
        PlaneSeparationReceipt(
            source_id="source-1",
            source_manifest_sha256="b" * 64,
            source_fields=("a", "b"),
            assignments=(
                FieldPlaneAssignment(
                    field_name="a", plane=EvidencePlane.MODEL_VISIBLE, rationale="input"
                ),
                FieldPlaneAssignment(
                    field_name="a", plane=EvidencePlane.TRUTH_ONLY, rationale="duplicate"
                ),
            ),
            parser_coverage=binding,
            evidence_manifest=binding,
            truth_manifest=binding,
            evidence_incident_ids_sha256="c" * 64,
            truth_incident_ids_sha256="c" * 64,
            produced_at=BASE,
        )
    contract = acquisition_contract()
    weakened = contract.model_dump(mode="json")
    weakened["minimum_system_families"] = 2
    with pytest.raises(ValidationError, match="cannot weaken"):
        AcquisitionContract.model_validate(weakened)
    build_acquisition_tree(tmp_path)
    naive = read_json(tmp_path / "resource_usage.json")
    naive["measured_at"] = BASE.replace(tzinfo=None)
    with pytest.raises(ValidationError, match="timezone-aware"):
        ResourceUsage.model_validate(naive)


def test_recovery_and_outcome_windows_must_be_ordered(tmp_path: Path) -> None:
    build_acquisition_tree(tmp_path)
    recovery = read_json(tmp_path / "artifacts" / "incident-000" / "recovery-execution.json")
    recovery["started_at"] = BASE + timedelta(seconds=1)
    recovery["finished_at"] = BASE
    with pytest.raises(ValidationError, match="finish before"):
        RecoveryExecution.model_validate(recovery)
    outcome = read_json(tmp_path / "artifacts" / "incident-000" / "settled-outcome.json")
    outcome["window_started_at"] = BASE
    outcome["window_finished_at"] = BASE
    with pytest.raises(ValidationError, match="positive duration"):
        SettledOutcomeRecord.model_validate(outcome)


def test_report_authority_cannot_be_forged(tmp_path: Path) -> None:
    report = audit_acquisition(build_acquisition_tree(tmp_path), tmp_path)
    forged = report.model_dump(mode="json")
    forged["authorized_next_action"] = "Train now"
    with pytest.raises(ValidationError, match="does not follow"):
        AcquisitionAdmissionReport.model_validate(forged)


def test_report_eligible_incident_ids_must_be_unique(tmp_path: Path) -> None:
    report = audit_acquisition(build_acquisition_tree(tmp_path), tmp_path)
    forged = report.model_dump(mode="json")
    forged["eligible_incident_ids"][-1] = forged["eligible_incident_ids"][0]
    with pytest.raises(ValidationError, match="eligible incidents are not unique"):
        AcquisitionAdmissionReport.model_validate(forged)


def test_source_permission_registry_cannot_omit_decisions(tmp_path: Path) -> None:
    build_acquisition_tree(tmp_path)
    source = read_json(tmp_path / "sources" / "physical-source.json")
    source["permissions"] = [
        item for item in source["permissions"] if item["kind"] != PermissionKind.ACQUIRE.value
    ]
    with pytest.raises(ValidationError, match="every permission"):
        SourceManifest.model_validate(source)


def test_permission_decision_enum_preserves_unknown_as_non_allowance() -> None:
    assert PermissionDecision.UNKNOWN != PermissionDecision.ALLOWED


def test_source_uri_and_manifest_independence_branches_fail_closed(tmp_path: Path) -> None:
    build_acquisition_tree(tmp_path)
    source_path = tmp_path / "sources" / "physical-source.json"
    source = read_json(source_path)
    resource = source["resources"][0]
    for uri, message in (
        ("http://example.com/data", "must use"),
        ("https://user:password@example.com/data", "credentials"),
        ("https:///missing-authority", "name an authority"),
    ):
        candidate = deepcopy(resource)
        candidate["uri"] = uri
        with pytest.raises(ValidationError, match=message):
            SourceResource.model_validate(candidate)

    mutations = (
        ("approved_at", BASE.replace(tzinfo=None), "timezone-aware"),
        ("rights_reviewer_id", source["source_steward_id"], "must differ"),
        (
            "rights_reviewer_independence_group",
            source["source_steward_independence_group"],
            "must be independent",
        ),
    )
    for field, value, message in mutations:
        candidate = deepcopy(source)
        candidate[field] = value
        with pytest.raises(ValidationError, match=message):
            SourceManifest.model_validate(candidate)
    duplicate_resource = deepcopy(source)
    duplicate_resource["resources"].append(deepcopy(duplicate_resource["resources"][0]))
    with pytest.raises(ValidationError, match="resource IDs"):
        SourceManifest.model_validate(duplicate_resource)
    duplicate_restricted = deepcopy(source)
    duplicate_restricted["restricted_fields"] = ["secret", "secret"]
    with pytest.raises(ValidationError, match="restricted fields"):
        SourceManifest.model_validate(duplicate_restricted)


def test_manifest_time_and_registry_validators_cover_negative_controls(tmp_path: Path) -> None:
    build_acquisition_tree(tmp_path)
    plane = read_json(tmp_path / "common" / "plane-separation.json")
    duplicate_fields = deepcopy(plane)
    duplicate_fields["source_fields"] = ["telemetry", "telemetry", "fault_label"]
    with pytest.raises(ValidationError, match="inventory must be unique"):
        PlaneSeparationReceipt.model_validate(duplicate_fields)
    naive_plane = deepcopy(plane)
    naive_plane["produced_at"] = BASE.replace(tzinfo=None)
    with pytest.raises(ValidationError, match="timestamp must be timezone-aware"):
        PlaneSeparationReceipt.model_validate(naive_plane)

    dossier_path = tmp_path / "dossiers" / "incident-000.json"
    dossier = read_json(dossier_path)
    naive_review = deepcopy(dossier)
    naive_review["reviews"][0]["reviewed_at"] = BASE.replace(tzinfo=None)
    with pytest.raises(ValidationError, match="review timestamp"):
        IncidentDossier.model_validate(naive_review)
    unordered = deepcopy(dossier)
    unordered["timeline"]["test_started_at"] = BASE + timedelta(minutes=70)
    with pytest.raises(ValidationError, match="chronology is not ordered"):
        IncidentDossier.model_validate(unordered)
    naive_timeline = deepcopy(dossier)
    naive_timeline["timeline"]["test_started_at"] = BASE.replace(tzinfo=None)
    with pytest.raises(ValidationError, match="timezone-aware"):
        IncidentDossier.model_validate(naive_timeline)

    missing_role = deepcopy(dossier)
    missing_role["roles"] = missing_role["roles"][:-1]
    with pytest.raises(ValidationError, match="every role"):
        IncidentDossier.model_validate(missing_role)
    missing_review = deepcopy(dossier)
    missing_review["reviews"] = missing_review["reviews"][:-1]
    with pytest.raises(ValidationError, match="every review"):
        IncidentDossier.model_validate(missing_review)
    duplicate_clock = deepcopy(dossier)
    duplicate_clock["clocks"].append(deepcopy(duplicate_clock["clocks"][0]))
    with pytest.raises(ValidationError, match="clock domains"):
        IncidentDossier.model_validate(duplicate_clock)
    duplicate_time = deepcopy(dossier)
    duplicate_time["evidence_times"].append(deepcopy(duplicate_time["evidence_times"][0]))
    with pytest.raises(ValidationError, match="time bindings"):
        IncidentDossier.model_validate(duplicate_time)


def test_contract_and_report_cannot_change_frozen_authority(tmp_path: Path) -> None:
    contract = acquisition_contract()
    base = contract.model_dump(mode="json")
    wrong_permissions = deepcopy(base)
    wrong_permissions["required_permissions"] = [PermissionKind.ACQUIRE.value]
    with pytest.raises(ValidationError, match="required permissions"):
        AcquisitionContract.model_validate(wrong_permissions)
    wrong_domains = deepcopy(base)
    wrong_domains["required_domains"] = ["aerospace", "industrial"]
    with pytest.raises(ValidationError, match="domains are both required"):
        AcquisitionContract.model_validate(wrong_domains)
    for field_name, changed_value in (
        ("max_clock_alignment_error_ns", 99_999_999),
        ("max_clock_missing_fraction", 0.049),
    ):
        changed_clock_contract = deepcopy(base)
        changed_clock_contract[field_name] = changed_value
        with pytest.raises(ValidationError, match=field_name):
            AcquisitionContract.model_validate(changed_clock_contract)
    wrong_ceiling = deepcopy(base)
    wrong_ceiling["resource_ceiling"]["max_gpu_seconds"] = 1
    with pytest.raises(ValidationError, match="resource ceiling"):
        AcquisitionContract.model_validate(wrong_ceiling)

    report = audit_acquisition(build_acquisition_tree(tmp_path), tmp_path)
    forged = report.model_dump(mode="json")
    forged["forbidden_next_actions"] = []
    with pytest.raises(ValidationError, match="forbidden-action"):
        AcquisitionAdmissionReport.model_validate(forged)


def test_naive_recovery_and_outcome_timestamps_are_rejected(tmp_path: Path) -> None:
    build_acquisition_tree(tmp_path)
    recovery = read_json(tmp_path / "artifacts" / "incident-000" / "recovery-execution.json")
    recovery["started_at"] = BASE.replace(tzinfo=None)
    with pytest.raises(ValidationError, match="recovery timestamps"):
        RecoveryExecution.model_validate(recovery)
    outcome = read_json(tmp_path / "artifacts" / "incident-000" / "settled-outcome.json")
    outcome["window_started_at"] = BASE.replace(tzinfo=None)
    with pytest.raises(ValidationError, match="settled-window timestamps"):
        SettledOutcomeRecord.model_validate(outcome)


def test_role_enum_exposes_every_required_independence_assignment() -> None:
    assert RoleKind.SOURCE_STEWARD in set(RoleKind)
    assert RoleKind.OUTCOME_VERIFIER in set(RoleKind)


def test_signed_registry_and_evidence_models_reject_ambiguous_authority(
    tmp_path: Path,
) -> None:
    build_acquisition_tree(tmp_path)
    registry = read_json(tmp_path / "trust_registry.json")

    naive_attestation = deepcopy(registry)
    naive_attestation["issued_at"] = BASE.replace(tzinfo=None)
    with pytest.raises(ValidationError, match="trust-registry timestamp"):
        ActorTrustRegistry.model_validate(naive_attestation)

    duplicate_roles = deepcopy(registry["actors"][0])
    duplicate_roles["authorized_roles"] *= 2
    with pytest.raises(ValidationError, match="roles must be unique"):
        TrustedActor.model_validate(duplicate_roles)

    duplicate_actor = deepcopy(registry)
    duplicate_actor["actors"].append(deepcopy(duplicate_actor["actors"][0]))
    with pytest.raises(ValidationError, match="actor IDs"):
        ActorTrustRegistry.model_validate(duplicate_actor)

    duplicate_key = deepcopy(registry)
    duplicate_key["actors"][1]["public_key"] = duplicate_key["actors"][0]["public_key"]
    with pytest.raises(ValidationError, match="share signing keys"):
        ActorTrustRegistry.model_validate(duplicate_key)

    duplicate_role_owner = deepcopy(registry)
    duplicate_role_owner["actors"][1]["authorized_roles"] = duplicate_role_owner["actors"][0][
        "authorized_roles"
    ]
    with pytest.raises(ValidationError, match="multiple owners"):
        ActorTrustRegistry.model_validate(duplicate_role_owner)

    missing_role = deepcopy(registry)
    missing_role["actors"].pop()
    with pytest.raises(ValidationError, match="authorize every dossier role"):
        ActorTrustRegistry.model_validate(missing_role)

    source = read_json(tmp_path / "sources" / "physical-source.json")
    naive_resource = deepcopy(source["resources"][0])
    naive_resource["staged_at"] = BASE.replace(tzinfo=None)
    with pytest.raises(ValidationError, match="staging timestamp"):
        SourceResource.model_validate(naive_resource)

    evidence_manifest = read_json(tmp_path / "common" / "evidence-manifest.json")
    evidence_manifest["incident_ids"].append(evidence_manifest["incident_ids"][0])
    with pytest.raises(ValidationError, match="manifest IDs"):
        PlaneIncidentManifest.model_validate(evidence_manifest)

    candidate_registry = read_json(tmp_path / "candidate_registry.json")
    naive_candidate = deepcopy(candidate_registry)
    naive_candidate["produced_at"] = BASE.replace(tzinfo=None)
    with pytest.raises(ValidationError, match="registry timestamp"):
        AcquisitionCandidateRegistry.model_validate(naive_candidate)
    duplicate_candidate = deepcopy(candidate_registry)
    duplicate_candidate["candidates"][1]["incident_id"] = duplicate_candidate["candidates"][0][
        "incident_id"
    ]
    with pytest.raises(ValidationError, match="candidate incident IDs"):
        AcquisitionCandidateRegistry.model_validate(duplicate_candidate)
    duplicate_root = deepcopy(candidate_registry)
    duplicate_root["candidates"][1]["root_incident_group_id"] = duplicate_root["candidates"][0][
        "root_incident_group_id"
    ]
    with pytest.raises(ValidationError, match="physical roots"):
        AcquisitionCandidateRegistry.model_validate(duplicate_root)

    dossier = read_json(tmp_path / "dossiers" / "incident-000.json")
    sequence = read_json(tmp_path / dossier["evidence_sequence"]["path"])
    naive_sequence = deepcopy(sequence)
    naive_sequence["produced_at"] = BASE.replace(tzinfo=None)
    with pytest.raises(ValidationError, match="sequence receipt timestamp"):
        EvidenceSequenceReceipt.model_validate(naive_sequence)
    duplicate_stream = deepcopy(sequence)
    duplicate_stream["streams"].append(deepcopy(duplicate_stream["streams"][0]))
    with pytest.raises(ValidationError, match="evidence IDs"):
        EvidenceSequenceReceipt.model_validate(duplicate_stream)

    custody = read_json(tmp_path / dossier["truth_custody"]["path"])
    naive_custody = deepcopy(custody)
    naive_custody["committed_at"] = BASE.replace(tzinfo=None)
    with pytest.raises(ValidationError, match="custody timestamps"):
        TruthCustodyReceipt.model_validate(naive_custody)
    reversed_custody = deepcopy(custody)
    reversed_custody["unsealed_at"] = reversed_custody["committed_at"]
    with pytest.raises(ValidationError, match="unseal must follow"):
        TruthCustodyReceipt.model_validate(reversed_custody)


def test_frozen_control_and_review_registries_reject_self_assertion(tmp_path: Path) -> None:
    build_acquisition_tree(tmp_path)
    control = read_json(tmp_path / "control_suite_receipt.json")
    mutations = (
        ("timestamp", lambda value: value.update(executed_at=BASE.replace(tzinfo=None))),
        ("exact frozen control set", lambda value: value["controls"].pop()),
        (
            "pytest nodes must be unique",
            lambda value: value["controls"][1].update(
                pytest_node_id=value["controls"][0]["pytest_node_id"]
            ),
        ),
        (
            "frozen control requirement",
            lambda value: value["controls"][0].update(expected_verdict="INVALID"),
        ),
        (
            "unexpected outcome",
            lambda value: value["controls"][0].update(passed=False),
        ),
    )
    for message, mutate in mutations:
        candidate = deepcopy(control)
        mutate(candidate)
        with pytest.raises(ValidationError, match=message):
            AdmissionControlSuiteReceipt.model_validate(candidate)

    shortcut = read_json(tmp_path / "shortcut_baseline.json")
    for field, value, message in (
        ("evaluated_at", BASE.replace(tzinfo=None), "shortcut report timestamp"),
        ("results", shortcut["results"][:-1], "exact frozen rule set"),
    ):
        candidate = deepcopy(shortcut)
        candidate[field] = value
        with pytest.raises(ValidationError, match=message):
            ShortcutBaselineReport.model_validate(candidate)
    truth_access = deepcopy(shortcut)
    truth_access["results"][0]["truth_access"] = True
    with pytest.raises(ValidationError, match="cannot access truth"):
        ShortcutBaselineReport.model_validate(truth_access)

    comparators = read_json(tmp_path / "intervention_comparators.json")
    naive_comparators = deepcopy(comparators)
    naive_comparators["committed_at"] = BASE.replace(tzinfo=None)
    with pytest.raises(ValidationError, match="comparator-registry timestamp"):
        InterventionComparatorRegistry.model_validate(naive_comparators)
    incomplete_comparators = deepcopy(comparators)
    incomplete_comparators["comparators"].pop()
    with pytest.raises(ValidationError, match="registry is incomplete"):
        InterventionComparatorRegistry.model_validate(incomplete_comparators)

    protocol = read_json(tmp_path / "protocol_reviews.json")
    naive_review = deepcopy(protocol["reviews"][0])
    naive_review["reviewed_at"] = BASE.replace(tzinfo=None)
    with pytest.raises(ValidationError, match="protocol-review timestamp"):
        ProtocolReviewRecord.model_validate(naive_review)
    incomplete_protocol = deepcopy(protocol)
    incomplete_protocol["reviews"].pop()
    with pytest.raises(ValidationError, match="cover aerospace and robotics"):
        ProtocolReviewRegistry.model_validate(incomplete_protocol)
    unapproved_protocol = deepcopy(protocol)
    unapproved_protocol["reviews"][0]["approved_for_physical_execution"] = False
    with pytest.raises(ValidationError, match="has not approved"):
        ProtocolReviewRegistry.model_validate(unapproved_protocol)


def test_leakage_scanner_is_bounded_and_covers_json_and_opaque_modes(tmp_path: Path) -> None:
    json_payload = b'{"events":[{"fault_label":"unit-identity"}]}'
    json_path = tmp_path / "input.json"
    json_path.write_bytes(json_payload)
    json_binding = ArtifactBinding(
        path="input.json",
        sha256=sha256_file(json_path),
        bytes=len(json_payload),
        media_type="application/json",
    )
    opaque_payload = b"x" * (64 * 1024 - 4) + b"unit-identity"
    opaque_path = tmp_path / "input.bin"
    opaque_path.write_bytes(opaque_payload)
    opaque_binding = ArtifactBinding(
        path="input.bin",
        sha256=sha256_file(opaque_path),
        bytes=len(opaque_payload),
        media_type="application/octet-stream",
    )

    report = build_model_visible_leakage_scan(
        tmp_path,
        incident_id="incident-scan",
        artifacts=(json_binding, opaque_binding),
        identity_values=("abc", "unit-identity"),
    )
    assert report.leakage_detected is True
    assert [scan.scan_mode for scan in report.artifact_scans] == ["utf8_json", "opaque_stream"]
    assert report.artifact_scans[0].forbidden_field_paths == ("$.events[0].fault_label",)
    assert report.artifact_scans[1].matched_identity_token_sha256

    oversized_total = opaque_binding.model_copy(update={"bytes": 512 * 1024 * 1024 + 1})
    with pytest.raises(AcquisitionAuditError, match="input byte ceiling"):
        build_model_visible_leakage_scan(
            tmp_path,
            incident_id="incident-scan",
            artifacts=(oversized_total,),
            identity_values=(),
        )
    oversized_artifact = opaque_binding.model_copy(update={"bytes": 256 * 1024 * 1024 + 1})
    with pytest.raises(AcquisitionAuditError, match="artifact byte ceiling"):
        build_model_visible_leakage_scan(
            tmp_path,
            incident_id="incident-scan",
            artifacts=(oversized_artifact,),
            identity_values=(),
        )

    duplicate_json = tmp_path / "duplicate.json"
    duplicate_json.write_bytes(b'{"signal":1,"signal":2}')
    duplicate_binding = ArtifactBinding(
        path="duplicate.json",
        sha256=sha256_file(duplicate_json),
        bytes=duplicate_json.stat().st_size,
        media_type="application/json",
    )
    with pytest.raises(AcquisitionAuditError, match="duplicate JSON key"):
        build_model_visible_leakage_scan(
            tmp_path,
            incident_id="incident-scan",
            artifacts=(duplicate_binding,),
            identity_values=(),
        )


def test_report_derivation_and_atomic_output_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_root = tmp_path / "input"
    report = audit_acquisition(build_acquisition_tree(input_root), input_root)
    forged = report.model_dump(mode="json")
    forged["gates"] = forged["gates"][:-1]
    with pytest.raises(ValidationError, match="gate registry is not exact"):
        AcquisitionAdmissionReport.model_validate(forged)

    forged = report.model_dump(mode="json")
    forged["gates"][1]["status"] = "invalid"
    with pytest.raises(ValidationError, match="impossible gate status"):
        AcquisitionAdmissionReport.model_validate(forged)

    forged = report.model_dump(mode="json")
    forged["verdict"] = "BLOCKED_ACQUISITION"
    forged["authorized_next_action"] = (
        "Acquire additional prospective physical dossiers under separate resource and safety "
        "authorities; training remains forbidden."
    )
    with pytest.raises(ValidationError, match="verdict does not follow"):
        AcquisitionAdmissionReport.model_validate(forged)

    forged = report.model_dump(mode="json")
    forged["eligible_incident_ids"] = forged["eligible_incident_ids"][:29]
    with pytest.raises(ValidationError, match="minimum eligible incident count"):
        AcquisitionAdmissionReport.model_validate(forged)

    forged = report.model_dump(mode="json")
    forged["eligible_incident_ids"][0] = "incident-unregistered"
    with pytest.raises(ValidationError, match="absent from the candidate registry"):
        AcquisitionAdmissionReport.model_validate(forged)

    output_root = tmp_path / "result"
    write_admission_output(output_root, report)
    assert (output_root / "admission_report.json").is_file()
    assert "not publication evidence" in render_admission_result(report).decode("ascii")
    with pytest.raises(AcquisitionAuditError, match="must not already exist"):
        write_admission_output(output_root, report)

    failed_output = tmp_path / "failed-result"

    def fail_write(path: Path, data: bytes) -> None:
        del path, data
        raise OSError("injected atomic-write failure")

    monkeypatch.setattr("fieldtrue.acquisition.atomic_write", fail_write)
    with pytest.raises(OSError, match="injected atomic-write failure"):
        write_admission_output(failed_output, report)
    assert not failed_output.exists()
    assert not list(tmp_path.glob(".failed-result.*"))
