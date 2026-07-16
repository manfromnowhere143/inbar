from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from importlib import metadata
from pathlib import Path
from types import ModuleType

import pytest
from pydantic import ValidationError

import fieldtrue.runtime as runtime_module
from fieldtrue.canonical import sha256_bytes
from fieldtrue.runtime import (
    DirtyRepositoryError,
    RuntimeIdentity,
    RuntimeProvenanceError,
    collect_runtime_identity,
)
from fieldtrue.schemas import export_schemas, schema_documents, verify_schemas

_GIT = shutil.which("git")
if _GIT is None:
    raise RuntimeError("git executable is required for runtime tests")

_OBSERVED_PROVENANCE = runtime_module._ObservedExecutionProvenance(
    python_interpreter_provenance_sha256="1" * 64,
    startup_provenance_sha256="2" * 64,
    environment_provenance_sha256="3" * 64,
    fieldtrue_source_sha256="4" * 64,
    loaded_module_closure_sha256="5" * 64,
    dependency_closure_sha256="6" * 64,
)


def _git(repo: Path, *arguments: str) -> None:
    subprocess.run(  # noqa: S603 - executable is resolved once from the test environment
        [_GIT, *arguments],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )


def _clean_git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    (repo / "uv.lock").write_text("lock-version = 1\n")
    (repo / "tracked.txt").write_text("frozen\n")
    _git(repo, "add", ".")
    _git(
        repo,
        "-c",
        "user.name=Proof Test",
        "-c",
        "user.email=proof@example.invalid",
        "commit",
        "-m",
        "fixture",
    )
    return repo


def _stub_execution_provenance(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        runtime_module,
        "_observe_execution_provenance",
        lambda *_args, **_kwargs: _OBSERVED_PROVENANCE,
    )


def test_schema_export_detects_stale_missing_and_unexpected_files(tmp_path: Path) -> None:
    documents = schema_documents()
    assert "approval_receipt.schema.json" in documents
    assert "shortcut_owner_approval_receipt.schema.json" in documents
    assert "shortcut_v2_exact_gini_tree.schema.json" in documents
    assert "shortcut_v2_crossfit_fold_registry.schema.json" in documents
    assert "shortcut_v2_target_envelope.schema.json" in documents
    assert "shortcut_implementation_authority_verification.schema.json" not in documents
    paths = export_schemas(tmp_path)
    assert len(paths) == len(documents)
    assert verify_schemas(tmp_path) == []

    paths[0].write_text("{}\n")
    (paths[0].parent / "unexpected.json").write_text("{}\n")
    errors = verify_schemas(tmp_path)
    assert any("stale schema" in error for error in errors)
    assert any("unexpected schema" in error for error in errors)
    paths[1].unlink()
    assert any("missing schema" in error for error in verify_schemas(tmp_path))


def test_committed_schemas_match_runtime_contracts() -> None:
    repo = Path(__file__).resolve().parents[2]
    assert verify_schemas(repo) == []


def test_claim_schema_exposes_evidence_path_and_lineage_constraints() -> None:
    schema = json.loads(schema_documents()["claim_record.schema.json"])
    evidence = schema["properties"]["evidence_refs"]

    assert evidence["minItems"] == 1
    assert evidence["uniqueItems"] is True
    assert evidence["items"]["pattern"]
    assert schema["properties"]["supersedes_claim_id"]["anyOf"][1] == {"type": "null"}


def test_engineering_validation_receipt_schema_exposes_epistemic_boundaries() -> None:
    schema = json.loads(schema_documents()["engineering_validation_receipt.schema.json"])

    assert schema["additionalProperties"] is False
    assert {
        "schema_version",
        "subject_commit",
        "subject_tree",
        "plan_sha256",
        "assurance_scope",
        "independent_attestation",
        "resource_accounting",
        "scientific_result",
        "authority_effect",
        "result",
    } <= set(schema["required"])
    assert schema["properties"]["assurance_scope"]["const"] == (
        "same-operator-engineering-observation-no-independent-attestation"
    )
    assert schema["properties"]["independent_attestation"] == {
        "const": False,
        "title": "Independent Attestation",
        "type": "boolean",
    }
    assert schema["properties"]["plan_sha256"]["pattern"] == r"^[0-9a-f]{64}$"
    assert schema["properties"]["steps"]["minItems"] == 1
    mission = schema["$defs"]["EngineeringValidationMissionObservation"]
    for field in (
        "mission_check_ids",
        "expected_blockers",
        "observed_blockers",
        "missing_expected_blockers",
        "unexpected_blockers",
    ):
        assert mission["properties"][field]["uniqueItems"] is True
    assert mission["properties"]["step_id"]["const"] == "mission-validate"
    pytest_observation = schema["$defs"]["EngineeringValidationPytestObservation"]
    assert pytest_observation["properties"]["step_id"]["const"] == "pytest-cov"
    assert pytest_observation["properties"]["tests_skipped"]["const"] == 0
    for field in ("tests_passed", "num_statements", "num_branches"):
        assert pytest_observation["properties"][field]["exclusiveMinimum"] == 0
    resources = schema["$defs"]["EngineeringValidationResourceAccounting"]
    assert resources["properties"]["measurement_status"]["const"] == "not_metered"
    for field in ("direct_cost_usd", "gpu_seconds", "cloud_jobs", "paid_calls"):
        assert resources["properties"][field]["type"] == "null"


def test_runtime_identity_schema_enforces_complete_provenance_states() -> None:
    schema = json.loads(schema_documents()["runtime_identity.schema.json"])
    alternatives = schema["allOf"][0]["oneOf"]
    legacy, observed = alternatives
    provenance_fields = {
        "python_interpreter_provenance_sha256",
        "startup_provenance_sha256",
        "environment_provenance_sha256",
        "fieldtrue_source_sha256",
        "loaded_module_closure_sha256",
        "dependency_closure_sha256",
    }

    assert legacy["properties"]["provenance_state"] == {"const": "legacy-unbound"}
    assert all(legacy["properties"][field] == {"type": "null"} for field in provenance_fields)
    assert observed["properties"]["provenance_state"] == {"const": "observed-v1"}
    assert set(observed["required"]) == {"provenance_state", *provenance_fields}
    assert all(
        observed["properties"][field] == {"type": "string", "pattern": r"^[0-9a-f]{64}$"}
        for field in provenance_fields
    )


def test_shortcut_v2_schemas_require_explicit_authority_constants() -> None:
    documents = schema_documents()
    tree = json.loads(documents["shortcut_v2_exact_gini_tree.schema.json"])
    assert {
        "schema_version",
        "algorithm",
        "maximum_depth",
        "minimum_child_incidents",
    } <= set(tree["required"])
    feature_vector = json.loads(documents["shortcut_v2_feature_vector.schema.json"])
    assert "kind" in feature_vector["$defs"]["BooleanFeatureValue"]["required"]
    assert "operator" in tree["$defs"]["EqualsBooleanPredicate"]["required"]
    assert "depth" in tree["$defs"]["DepthOneTreeNode"]["required"]

    envelope = json.loads(documents["shortcut_v2_target_envelope.schema.json"])
    assert "schema_version" in envelope["required"]
    assert "incident_id" in envelope["$defs"]["TargetSubsetEntry"]["required"]
    assert (
        len(envelope["$defs"]["RuleAxisFoldAuthoritySubject"]["properties"]["rule_id"]["enum"])
        == 10
    )
    context = envelope["$defs"]["ShortcutReleaseContext"]
    assert {"schema_version", "domain", "iteration_id"} <= set(context["required"])
    for field in (
        "proposal_git_commit",
        "amendment_document_artifact_sha256",
        "machine_proposal_artifact_sha256",
        "owner_approval_receipt_sha256",
    ):
        assert "const" in context["properties"][field]
    prerequisite_map = context["properties"]["prerequisite_artifacts"]
    assert prerequisite_map["additionalProperties"] is False
    assert prerequisite_map["propertyNames"] == {"pattern": r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"}

    for filename in (
        "shortcut_owner_approval_receipt.schema.json",
        "shortcut_attestation.schema.json",
        "shortcut_v2_crossfit_census.schema.json",
        "shortcut_v2_crossfit_fold.schema.json",
        "shortcut_v2_crossfit_fold_registry.schema.json",
        "shortcut_v2_categorical_fitted_state.schema.json",
        "shortcut_v2_categorical_prediction_manifest.schema.json",
        "shortcut_v2_tree_fitted_state.schema.json",
        "shortcut_v2_tree_prediction.schema.json",
        "shortcut_v2_tree_prediction_manifest.schema.json",
        "shortcut_v2_x25519_recipient_identity.schema.json",
    ):
        schema = json.loads(documents[filename])
        assert "schema_version" in schema["required"], filename


def test_runtime_identity_binds_clean_git_tree_lock_and_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _clean_git_repo(tmp_path)
    _stub_execution_provenance(monkeypatch)
    fake_git = tmp_path / "git"
    fake_git.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
    fake_git.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setenv("GIT_DIR", "/does/not/exist")
    monkeypatch.setenv("GIT_WORK_TREE", "/does/not/exist")
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", "/does/not/exist")
    monkeypatch.setenv("GIT_ALTERNATE_OBJECT_DIRECTORIES", "/does/not/exist")
    identity = collect_runtime_identity(
        repo,
        command=("mission", "run"),
    )
    assert len(identity.git_commit) == 40
    assert len(identity.git_tree) == 40
    assert not identity.repository_dirty
    assert identity.command == ("mission", "run")
    assert identity.provenance_state == "observed-v1"
    assert identity.python_interpreter_provenance_sha256 == "1" * 64
    assert identity.dependency_closure_sha256 == "6" * 64
    identity.require_observed_provenance()

    (repo / "tracked.txt").write_text("changed\n")
    with pytest.raises(DirtyRepositoryError, match="clean Git"):
        collect_runtime_identity(repo, command=("mission", "run"))
    dirty = collect_runtime_identity(
        repo,
        command=("mission", "run"),
        require_clean=False,
    )
    assert dirty.repository_dirty
    assert dirty.dirty_state_hash == sha256_bytes(b" M tracked.txt\n")


def test_runtime_requires_lockfile(tmp_path: Path) -> None:
    repo = _clean_git_repo(tmp_path)
    (repo / "uv.lock").unlink()
    with pytest.raises(FileNotFoundError, match=r"uv\.lock"):
        collect_runtime_identity(repo, command=("run",), require_clean=False)


def test_runtime_stable_read_rejects_chmod_restore_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "runtime-artifact"
    path.write_bytes(b"stable bytes")
    path.chmod(0o640)
    initial_ctime_ns = path.stat().st_ctime_ns
    original_read = runtime_module.os.read
    raced = False

    def racing_read(descriptor: int, maximum_bytes: int) -> bytes:
        nonlocal raced
        if not raced:
            raced = True
            time.sleep(0.01)
            path.chmod(0o600)
            path.chmod(0o640)
        return original_read(descriptor, maximum_bytes)

    monkeypatch.setattr(runtime_module.os, "read", racing_read)

    with pytest.raises(RuntimeProvenanceError, match="changed while it was read"):
        runtime_module._stable_regular_bytes(path, maximum_bytes=1024)
    assert raced
    assert path.stat().st_mode & 0o777 == 0o640
    assert path.stat().st_ctime_ns != initial_ctime_ns
    assert {"st_ctime_ns", "st_gid"}.issubset(runtime_module._STABLE_STAT_FIELDS)


def test_runtime_rejects_mutation_during_final_repository_trust_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _clean_git_repo(tmp_path)
    _stub_execution_provenance(monkeypatch)
    original = runtime_module.trusted_repository_git
    calls = 0

    def mutate_on_second_trust_call(repo_root: Path) -> str:
        nonlocal calls
        git = original(repo_root)
        calls += 1
        if calls == 2:
            (repo_root / "tracked.txt").write_text("changed during trust\n", encoding="utf-8")
        return git

    monkeypatch.setattr(runtime_module, "trusted_repository_git", mutate_on_second_trust_call)
    with pytest.raises(DirtyRepositoryError, match="worktree changed"):
        collect_runtime_identity(repo, command=("run",))
    assert calls == 2


def test_runtime_rejects_head_change_during_final_repository_trust_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _clean_git_repo(tmp_path)
    _stub_execution_provenance(monkeypatch)
    original = runtime_module.trusted_repository_git
    calls = 0

    def commit_on_second_trust_call(repo_root: Path) -> str:
        nonlocal calls
        git = original(repo_root)
        calls += 1
        if calls == 2:
            (repo_root / "tracked.txt").write_text("new commit\n", encoding="utf-8")
            _git(repo_root, "add", "tracked.txt")
            _git(
                repo_root,
                "-c",
                "user.name=Proof Test",
                "-c",
                "user.email=proof@example.invalid",
                "commit",
                "-m",
                "mutate head during trust",
            )
        return git

    monkeypatch.setattr(runtime_module, "trusted_repository_git", commit_on_second_trust_call)
    with pytest.raises(DirtyRepositoryError, match="HEAD changed"):
        collect_runtime_identity(repo, command=("run",))
    assert calls == 2


def test_runtime_rejects_hidden_lock_change_during_final_repository_trust_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _clean_git_repo(tmp_path)
    _stub_execution_provenance(monkeypatch)
    original = runtime_module.trusted_repository_git
    calls = 0

    def mutate_lock_on_second_trust_call(repo_root: Path) -> str:
        nonlocal calls
        git = original(repo_root)
        calls += 1
        if calls == 2:
            (repo_root / "uv.lock").write_text("lock-version = 2\n", encoding="utf-8")
            _git(repo_root, "update-index", "--assume-unchanged", "uv.lock")
        return git

    monkeypatch.setattr(runtime_module, "trusted_repository_git", mutate_lock_on_second_trust_call)
    with pytest.raises(DirtyRepositoryError, match=r"uv\.lock changed"):
        collect_runtime_identity(repo, command=("run",))
    assert calls == 2


def test_runtime_identity_parses_historical_receipt_as_explicitly_unbound() -> None:
    identity = RuntimeIdentity.model_validate(
        {
            "git_commit": "a" * 40,
            "git_tree": "b" * 40,
            "repository_dirty": False,
            "dirty_state_hash": "c" * 64,
            "lockfile_hash": "d" * 64,
            "python_version": "3.12.2",
            "platform": "test-platform",
            "command": ["fieldtrue", "experiment", "iter000"],
        }
    )

    assert identity.provenance_state == "legacy-unbound"
    assert identity.python_interpreter_provenance_sha256 is None
    assert identity.dependency_closure_sha256 is None
    assert "provenance_state" not in identity.model_dump(mode="json")
    with pytest.raises(RuntimeProvenanceError, match="requires observed-v1"):
        identity.require_observed_provenance()


def test_runtime_identity_rejects_partial_or_false_provenance_claims() -> None:
    common = {
        "git_commit": "a" * 40,
        "git_tree": "b" * 40,
        "repository_dirty": False,
        "dirty_state_hash": "c" * 64,
        "lockfile_hash": "d" * 64,
        "python_version": "3.12.2",
        "platform": "test-platform",
        "command": ["run"],
    }
    with pytest.raises(ValidationError, match="requires every provenance hash"):
        RuntimeIdentity.model_validate({**common, "provenance_state": "observed-v1"})
    with pytest.raises(ValidationError, match="cannot claim provenance hashes"):
        RuntimeIdentity.model_validate({**common, "python_interpreter_provenance_sha256": "e" * 64})


def test_runtime_identity_revalidates_unsafe_model_copy_mutations() -> None:
    common = {
        "git_commit": "a" * 40,
        "git_tree": "b" * 40,
        "repository_dirty": False,
        "dirty_state_hash": "c" * 64,
        "lockfile_hash": "d" * 64,
        "python_version": "3.12.2",
        "platform": "test-platform",
        "command": ("run",),
    }
    legacy = RuntimeIdentity.model_validate(common)
    promoted = legacy.model_copy(update={"provenance_state": "observed-v1"})

    with pytest.raises(RuntimeProvenanceError, match="full strict provenance revalidation"):
        promoted.require_observed_provenance()
    with pytest.raises(ValidationError, match="requires every provenance hash"):
        RuntimeIdentity.model_validate(promoted)

    observed = RuntimeIdentity.model_validate(
        {
            **common,
            "provenance_state": "observed-v1",
            "python_interpreter_provenance_sha256": "1" * 64,
            "startup_provenance_sha256": "2" * 64,
            "environment_provenance_sha256": "3" * 64,
            "fieldtrue_source_sha256": "4" * 64,
            "loaded_module_closure_sha256": "5" * 64,
            "dependency_closure_sha256": "6" * 64,
        }
    )
    corrupted = (
        observed.model_copy(update={"dependency_closure_sha256": 7}),
        observed.model_copy(update={"command": "run"}),
    )
    for candidate in corrupted:
        with pytest.raises(RuntimeProvenanceError, match="full strict provenance revalidation"):
            candidate.require_observed_provenance()


@pytest.mark.parametrize("variable", ["PYTHONPATH", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES"])
def test_runtime_rejects_ambient_startup_injection(
    monkeypatch: pytest.MonkeyPatch,
    variable: str,
) -> None:
    monkeypatch.setenv(variable, str(Path.cwd()))
    with pytest.raises(RuntimeProvenanceError, match=variable):
        runtime_module._snapshot_environment()


def test_runtime_rejects_sitecustomize_even_after_it_erases_pythonpath(tmp_path: Path) -> None:
    (tmp_path / "sitecustomize.py").write_text(
        "import os\n"
        "os.environ['INBAR_SITE_EXECUTED'] = 'yes'\n"
        "os.environ.pop('PYTHONPATH', None)\n",
        encoding="utf-8",
    )
    repo = Path(__file__).resolve().parents[2]
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(tmp_path)
    script = (
        "import os\n"
        "from pathlib import Path\n"
        "import fieldtrue.runtime as runtime\n"
        "assert os.environ.get('INBAR_SITE_EXECUTED') == 'yes'\n"
        "assert 'PYTHONPATH' not in os.environ\n"
        "try:\n"
        "    roots = runtime._resolved_roots(Path.cwd())\n"
        "    runtime._startup_provenance(Path.cwd(), roots)\n"
        "except runtime.RuntimeProvenanceError as error:\n"
        "    print(error)\n"
        "else:\n"
        "    raise SystemExit(7)\n"
    )

    completed = subprocess.run(  # noqa: S603 - current test interpreter is intentional
        [sys.executable, "-c", script],
        cwd=repo,
        check=True,
        capture_output=True,
        env=environment,
        text=True,
        timeout=20,
    )

    assert "unbound Python startup module was loaded: sitecustomize" in completed.stdout


def test_startup_and_environment_observations_change_without_exposing_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = Path(__file__).resolve().parents[2]
    roots = runtime_module._resolved_roots(repo)
    startup_before = runtime_module._startup_provenance(repo, roots)
    monkeypatch.setattr(sys, "argv", [*sys.argv, "provenance-probe"])
    startup_after = runtime_module._startup_provenance(repo, roots)
    assert startup_before != startup_after

    monkeypatch.setenv("INBAR_TEST_SECRET", "do-not-emit-this-value")
    environment = runtime_module._snapshot_environment()
    digest = runtime_module._environment_provenance(environment)
    assert len(digest) == 64
    assert "do-not-emit-this-value" not in digest
    monkeypatch.setenv("INBAR_TEST_SECRET", "changed-secret-value")
    changed = runtime_module._environment_provenance(runtime_module._snapshot_environment())
    assert changed != digest


def test_fieldtrue_source_and_loaded_module_closures_change_with_content_or_census(
    tmp_path: Path,
) -> None:
    source = tmp_path / "fieldtrue"
    source.mkdir()
    module_path = source / "example.py"
    module_path.write_text("VALUE = 1\n", encoding="utf-8")
    first_source = runtime_module._tree_provenance(source)
    module_path.write_text("VALUE = 2\n", encoding="utf-8")
    second_source = runtime_module._tree_provenance(source)
    assert first_source != second_source

    repo = Path(__file__).resolve().parents[2]
    roots = runtime_module._resolved_roots(repo)
    probe = ModuleType("inbar_runtime_provenance_probe")
    probe.__file__ = str(repo / "src" / "fieldtrue" / "runtime.py")
    first_modules = runtime_module._module_provenance(
        repo,
        roots,
        modules=(("fieldtrue.runtime", runtime_module),),
    )
    second_modules = runtime_module._module_provenance(
        repo,
        roots,
        modules=(
            ("fieldtrue.runtime", runtime_module),
            (probe.__name__, probe),
        ),
    )
    assert first_modules != second_modules


def _record_hash(data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return f"sha256={digest.decode('ascii')}"


def test_dependency_provenance_verifies_recorded_file_bytes(tmp_path: Path) -> None:
    runtime_prefix = tmp_path / "runtime"
    site_root = runtime_prefix / "lib" / "python3.12" / "site-packages"
    package_root = site_root / "example_dependency"
    dist_info = site_root / "example_dependency-1.0.dist-info"
    package_root.mkdir(parents=True)
    dist_info.mkdir()
    script_path = runtime_prefix / "bin" / "example-tool"
    script_path.parent.mkdir(parents=True)
    package_data = b"VALUE = 'bound'\n"
    metadata_data = b"Metadata-Version: 2.1\nName: example-dependency\nVersion: 1.0\n\n"
    wheel_data = b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    script_data = b"#!/bin/sh\nexit 0\n"
    (package_root / "__init__.py").write_bytes(package_data)
    (dist_info / "METADATA").write_bytes(metadata_data)
    (dist_info / "WHEEL").write_bytes(wheel_data)
    script_path.write_bytes(script_data)
    record_rows = (
        f"example_dependency/__init__.py,{_record_hash(package_data)},{len(package_data)}\n"
        f"example_dependency-1.0.dist-info/METADATA,{_record_hash(metadata_data)},"
        f"{len(metadata_data)}\n"
        f"example_dependency-1.0.dist-info/WHEEL,{_record_hash(wheel_data)},"
        f"{len(wheel_data)}\n"
        f"../../../bin/example-tool,{_record_hash(script_data)},{len(script_data)}\n"
        "example_dependency-1.0.dist-info/RECORD,,\n"
    )
    (dist_info / "RECORD").write_text(record_rows, encoding="utf-8")
    distribution = metadata.Distribution.at(dist_info)
    roots = (("environment", runtime_prefix.resolve(strict=True)),)

    manifest, file_count, byte_count = runtime_module._distribution_manifest(
        distribution,
        expected_name="example-dependency",
        expected_version="1.0",
        roots=roots,
        runtime_prefix=runtime_prefix,
    )
    assert manifest["record_sha256"] == sha256_bytes(record_rows.encode("utf-8"))
    assert file_count == 5
    assert byte_count > len(package_data)

    (package_root / "__init__.py").write_bytes(b"VALUE = 'dirty'\n")
    with pytest.raises(RuntimeProvenanceError, match=r"RECORD (?:size|hash)"):
        runtime_module._distribution_manifest(
            distribution,
            expected_name="example-dependency",
            expected_version="1.0",
            roots=roots,
            runtime_prefix=runtime_prefix,
        )


@pytest.mark.parametrize("raw_path", ["../escape.py", "package/./module.py", "../../bin/tool"])
def test_dependency_record_rejects_non_console_script_traversal(
    tmp_path: Path,
    raw_path: str,
) -> None:
    runtime_prefix = tmp_path / "runtime"
    site_root = runtime_prefix / "lib" / "python3.12" / "site-packages"
    site_root.mkdir(parents=True)

    with pytest.raises(RuntimeProvenanceError, match=r"(?:path|traversal) is unsafe"):
        runtime_module._dependency_record_candidate(
            site_root,
            raw_path,
            runtime_prefix=runtime_prefix,
        )


def test_runtime_rejects_environment_mutation_during_final_provenance_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _clean_git_repo(tmp_path)
    calls = 0

    def observe(*_args: object, **_kwargs: object) -> runtime_module._ObservedExecutionProvenance:
        nonlocal calls
        calls += 1
        if calls == 2:
            os.environ["INBAR_MUTATED_DURING_IDENTITY"] = "yes"
        return _OBSERVED_PROVENANCE

    monkeypatch.setattr(runtime_module, "_observe_execution_provenance", observe)
    with pytest.raises(RuntimeProvenanceError, match="environment changed"):
        collect_runtime_identity(repo, command=("run",))
    assert calls == 2
