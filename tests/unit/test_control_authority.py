from __future__ import annotations

import errno
import os
import shutil
import signal
import subprocess
import sys
from contextlib import suppress
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import fieldtrue.control_authority as authority
import fieldtrue.control_launcher as launcher
import fieldtrue.control_observation as observation_plugin
import fieldtrue.control_producer as producer
from fieldtrue.acquisition import (
    _ACTIONS,
    _CONTROL_REQUIREMENTS,
    _REQUIRED_CONTROL_IDS,
    AcquisitionAdmissionReport,
    AcquisitionCandidateRegistry,
    AcquisitionContract,
    AcquisitionGateResult,
    AdmissionControlResult,
    AdmissionControlSuiteReceipt,
    ArtifactBinding,
)
from fieldtrue.canonical import (
    atomic_write,
    canonical_json_pretty,
    read_json,
    sha256_file,
    sha256_value,
)
from fieldtrue.control_authority import (
    ControlAuthorityError,
    _assert_clean_repo,
    _git_bound_source,
    _git_identity,
    _run_control,
    _validate_lifecycle,
    verify_admission_control_bundle,
)
from fieldtrue.control_launcher import generate_admission_control_bundle
from fieldtrue.control_observation import (
    ControlObservation,
    FixtureFile,
    FixtureSnapshot,
    PytestLifecycle,
    PytestPhase,
    pytest_collection_finish,
    pytest_configure,
    pytest_runtest_logreport,
    pytest_sessionfinish,
    record_control_exception,
    record_control_observation,
    snapshot_fixture_tree,
)
from fieldtrue.control_protocol import CONTROL_PRODUCER_KEY_PATH
from fieldtrue.receipts import load_or_create_signing_key

ZERO_HASH = "0" * 64
ZERO_BLOB = "0" * 40


def _execution_manifest_value() -> dict[str, Any]:
    return {
        "suite_id": "iter001-admission-controls-v1",
        "execution_commit": ZERO_BLOB,
        "execution_tree": "1" * 40,
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:01:00Z",
        "repository_clean_before": True,
        "repository_clean_after": True,
        "dependency_mode": "lock-hash-authenticated-wheels",
        "uv_executable": "/absolute/uv",
        "uv_executable_sha256": ZERO_HASH,
        "uv_version": "uv 1.0.0",
        "python_executable_sha256": ZERO_HASH,
        "python_version": "3.12.13",
        "runner_environment_sha256": ZERO_HASH,
        "artifact_set_sha256": ZERO_HASH,
        "source_closure_sha256": ZERO_HASH,
        "source_file_count": 1,
        "environment_policy": (),
        "sources": [
            {
                "name": name,
                "path": path,
                "git_blob": ZERO_BLOB,
                "sha256": ZERO_HASH,
                "bytes": 0,
            }
            for name, path in authority._SOURCE_PATHS
        ],
        "controls": [
            {
                "control_id": control_id,
                "pytest_node_id": _CONTROL_REQUIREMENTS[control_id][0],
                "expected_verdict": _CONTROL_REQUIREMENTS[control_id][1],
                "expected_gate_id": _CONTROL_REQUIREMENTS[control_id][2],
                "expected_failure_code": _CONTROL_REQUIREMENTS[control_id][3],
                "evidence": {
                    "path": f"controls/{control_id}.json",
                    "sha256": ZERO_HASH,
                    "bytes": 0,
                    "media_type": "application/json",
                },
            }
            for control_id in _REQUIRED_CONTROL_IDS
        ],
    }


def test_execution_manifest_binds_exact_ordered_source_name_path_pairs() -> None:
    manifest = authority.ControlExecutionManifest.model_validate(_execution_manifest_value())
    assert tuple((source.name, source.path) for source in manifest.sources) == (
        authority._SOURCE_PATHS
    )
    assert {
        ("acquisition_contract", "protocol/acquisition/iter001_contract.json"),
        ("project_config", "pyproject.toml"),
        ("tests_package_init", "tests/__init__.py"),
        ("unit_tests_package_init", "tests/unit/__init__.py"),
    }.issubset(set(authority._SOURCE_PATHS))

    substituted = _execution_manifest_value()
    substituted["sources"][0]["path"] = "src/fieldtrue/substituted.py"
    with pytest.raises(ValueError, match="source inventory is not exact"):
        authority.ControlExecutionManifest.model_validate(substituted)

    swapped = _execution_manifest_value()
    first_path = swapped["sources"][0]["path"]
    swapped["sources"][0]["path"] = swapped["sources"][1]["path"]
    swapped["sources"][1]["path"] = first_path
    with pytest.raises(ValueError, match="source inventory is not exact"):
        authority.ControlExecutionManifest.model_validate(swapped)


def test_execution_manifest_rejects_time_and_control_mutations() -> None:
    naive = _execution_manifest_value()
    naive["started_at"] = "2026-01-01T00:00:00"
    with pytest.raises(ValueError, match="timezone-aware"):
        authority.ControlExecutionManifest.model_validate(naive)

    reversed_time = _execution_manifest_value()
    reversed_time["finished_at"] = "2025-12-31T23:59:59Z"
    with pytest.raises(ValueError, match="finish precedes"):
        authority.ControlExecutionManifest.model_validate(reversed_time)

    substituted_control = _execution_manifest_value()
    substituted_control["controls"][0]["control_id"] = "substituted-control"
    with pytest.raises(ValueError, match="frozen controls exactly"):
        authority.ControlExecutionManifest.model_validate(substituted_control)


def test_preregistered_multimodal_and_approval_controls_are_frozen() -> None:
    expected = {
        "one-modality": (
            "tests/unit/test_acquisition.py::test_one_modality_case_is_invalid",
            "INVALID",
            "artifact-integrity",
            "one-modality",
        ),
        "stationary-image-proxy": (
            "tests/unit/test_acquisition.py::test_stationary_image_proxy_is_invalid",
            "INVALID",
            "artifact-integrity",
            "stationary-image-proxy",
        ),
        "shuffled-modality": (
            "tests/unit/test_acquisition.py::test_shuffled_modality_order_is_invalid",
            "INVALID",
            "artifact-integrity",
            "shuffled-modality",
        ),
        "forged-approval": (
            "tests/unit/test_acquisition.py::test_forged_test_approval_is_invalid",
            "INVALID",
            "artifact-integrity",
            "forged-approval",
        ),
    }

    assert tuple(control_id for control_id in _REQUIRED_CONTROL_IDS if control_id in expected) == (
        "one-modality",
        "stationary-image-proxy",
        "shuffled-modality",
        "forged-approval",
    )
    assert {control_id: _CONTROL_REQUIREMENTS[control_id] for control_id in expected} == expected


def _git(repo: Path, *arguments: str) -> None:
    subprocess.run(  # noqa: S603 - tests supply fixed Git arguments
        ("git", "-C", str(repo), *arguments),  # noqa: S607 - fixed Git executable
        check=True,
        capture_output=True,
    )


def _report(
    verdict: str,
    *gates: AcquisitionGateResult,
    eligible_incidents: tuple[str, ...] | None = None,
    candidate_incidents: tuple[str, ...] | None = None,
    candidate_registry_sha256: str = ZERO_HASH,
) -> AcquisitionAdmissionReport:
    statuses = {
        "artifact-integrity": "invalid" if verdict == "INVALID" else "pass",
        "source-rights": "blocked" if verdict == "BLOCKED_RIGHTS" else "pass",
        "resource-ceiling": "pass",
        "conjunctive-coverage": ("blocked" if verdict == "BLOCKED_ACQUISITION" else "pass"),
        "shortcut-baseline": "blocked" if verdict == "KILL_CONSTRUCT" else "pass",
    }
    gate_by_id = {
        gate_id: AcquisitionGateResult(
            gate_id=gate_id,
            status=status,
            observed={},
            requirement="frozen requirement",
            detail="fixture observation",
        )
        for gate_id, status in statuses.items()
    }
    gate_by_id.update({gate.gate_id: gate for gate in gates})
    if eligible_incidents is None:
        eligible_incidents = (
            tuple(f"incident-{index:03d}" for index in range(30))
            if verdict in {"PASS_PILOT", "KILL_CONSTRUCT"}
            else ()
        )
    if candidate_incidents is None:
        candidate_incidents = eligible_incidents
    return AcquisitionAdmissionReport.model_validate(
        {
            "authority_profile": "test_fixture",
            "iteration_id": "iter001_physical_causal_evidence_acquisition",
            "contract_sha256": ZERO_HASH,
            "validator_git_blob": ZERO_BLOB,
            "validator_source_sha256": ZERO_HASH,
            "trust_registry_sha256": ZERO_HASH,
            "control_suite_sha256": ZERO_HASH,
            "candidate_registry_sha256": candidate_registry_sha256,
            "comparator_registry_sha256": ZERO_HASH,
            "split_locks_sha256": ZERO_HASH,
            "corpus_sha256": ZERO_HASH,
            "resource_usage_sha256": ZERO_HASH,
            "candidate_incident_ids": candidate_incidents,
            "eligible_incident_ids": eligible_incidents,
            "gates": tuple(gate_by_id.values()),
            "verdict": verdict,
            "authorized_next_action": _ACTIONS[verdict],
            "forbidden_next_actions": (
                "GPU or learned-model training",
                "diagnosis, recovery, safety, transfer, product, or economic-value claim",
                "live robot, flight, spacecraft, or destructive authority",
            ),
        }
    )


def test_fixture_snapshot_is_content_addressed_and_sorted(tmp_path: Path) -> None:
    (tmp_path / "z").write_bytes(b"last")
    (tmp_path / "a").write_bytes(b"first")

    snapshot = snapshot_fixture_tree(tmp_path)

    assert [item.path for item in snapshot.files] == ["a", "z"]
    assert snapshot.root_sha256 == sha256_value(
        [item.model_dump(mode="json") for item in snapshot.files]
    )


def test_fixture_snapshot_rejects_symbolic_links(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"bound")
    (tmp_path / "alias").symlink_to(target)

    with pytest.raises(ControlAuthorityError, match="symbolic link"):
        snapshot_fixture_tree(tmp_path)


def test_fixture_snapshot_rejects_digest_order_and_empty_roots(tmp_path: Path) -> None:
    first = FixtureFile(path="a", sha256=ZERO_HASH, bytes=0)
    second = FixtureFile(path="b", sha256=ZERO_HASH, bytes=0)
    with pytest.raises(ValueError, match="digest is not derived"):
        FixtureSnapshot(files=(first,), root_sha256="1" * 64)

    reversed_files = (second, first)
    with pytest.raises(ValueError, match="sorted and unique"):
        FixtureSnapshot(
            files=reversed_files,
            root_sha256=sha256_value([item.model_dump(mode="json") for item in reversed_files]),
        )

    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ControlAuthorityError, match="fixture tree is empty"):
        snapshot_fixture_tree(empty)
    regular_file = tmp_path / "not-a-root"
    regular_file.write_bytes(b"bound")
    with pytest.raises(ControlAuthorityError, match="not a directory"):
        snapshot_fixture_tree(regular_file)


def test_fixture_snapshot_descends_directories_and_rejects_special_files(tmp_path: Path) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "artifact").write_bytes(b"bound")
    assert snapshot_fixture_tree(tmp_path).files[0].path == "nested/artifact"

    fifo = tmp_path / "untrusted-fifo"
    os.mkfifo(fifo)
    with pytest.raises(ControlAuthorityError, match="special file"):
        snapshot_fixture_tree(tmp_path)


def test_control_observation_is_absent_outside_generator(tmp_path: Path) -> None:
    (tmp_path / "fixture").write_bytes(b"bound")
    report = _report(
        "PASS_PILOT",
        AcquisitionGateResult(
            gate_id="artifact-integrity",
            status="pass",
            observed={"failures": []},
            requirement="integrity",
            detail="complete",
        ),
    )

    record_control_observation(tmp_path, report)

    assert list(tmp_path.iterdir()) == [tmp_path / "fixture"]


def test_control_environment_rejects_partial_unknown_and_substituted_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        observation_plugin._CONTROL_ENV,
        observation_plugin._NODE_ENV,
        observation_plugin._OBSERVATION_ENV,
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(observation_plugin._CONTROL_ENV, "valid-conjunctive-pilot")
    with pytest.raises(ControlAuthorityError, match="environment is incomplete"):
        observation_plugin._control_environment()

    monkeypatch.setenv(
        observation_plugin._NODE_ENV,
        "tests/unit/test_acquisition.py::test_substituted",
    )
    monkeypatch.setenv(observation_plugin._OBSERVATION_ENV, str(tmp_path / "observation.json"))
    with pytest.raises(ControlAuthorityError, match="node differs"):
        observation_plugin._control_environment()

    monkeypatch.setenv(observation_plugin._CONTROL_ENV, "unknown-control")
    with pytest.raises(ControlAuthorityError, match="unknown admission control"):
        observation_plugin._control_environment()


def test_sanitized_control_environment_is_an_explicit_allowlist(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PATH", "/controlled/bin")
    monkeypatch.setenv("TMPDIR", str(tmp_path / "tmp"))
    monkeypatch.setenv("UV_CACHE_DIR", str(tmp_path / "uv-cache"))
    monkeypatch.setenv("CLOUD_API_TOKEN", "must-not-propagate")

    environment = authority._sanitized_environment(
        control_id="valid-conjunctive-pilot",
        node_id=_CONTROL_REQUIREMENTS["valid-conjunctive-pilot"][0],
        observation_path=tmp_path / "observation.json",
        outcome_path=tmp_path / "lifecycle.json",
    )

    assert environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    assert environment["PYTHONDONTWRITEBYTECODE"] == "1"
    assert environment["HOME"] == "/nonexistent"
    assert environment["PATH"] == os.defpath
    assert "TMPDIR" not in environment
    assert "UV_CACHE_DIR" not in environment
    assert "CLOUD_API_TOKEN" not in environment


def test_generator_bound_observation_records_actual_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture_root = tmp_path / "fixture"
    fixture_root.mkdir()
    (fixture_root / "artifact").write_bytes(b"bound")
    output = tmp_path / "observation.json"
    node = "tests/unit/test_acquisition.py::test_complete_conjunctive_pilot_passes"
    monkeypatch.setenv("FIELDTRUE_CONTROL_ID", "valid-conjunctive-pilot")
    monkeypatch.setenv("FIELDTRUE_CONTROL_NODE_ID", node)
    monkeypatch.setenv("FIELDTRUE_CONTROL_OBSERVATION_PATH", str(output))
    report = _report(
        "PASS_PILOT",
        AcquisitionGateResult(
            gate_id="artifact-integrity",
            status="pass",
            observed={"failures": []},
            requirement="integrity",
            detail="complete",
        ),
    )

    record_control_observation(fixture_root, report)
    observation = ControlObservation.model_validate(read_json(output))

    assert observation.report_sha256 == sha256_value(report.model_dump(mode="json"))
    assert observation.fixture.root_sha256 == snapshot_fixture_tree(fixture_root).root_sha256
    assert observation.observed_gate_id == "admission"
    assert observation.observed_failure_code is None
    with pytest.raises(FileExistsError):
        record_control_observation(fixture_root, report)


def test_count_intersection_requires_a_bound_candidate_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture_root = tmp_path / "fixture"
    fixture_root.mkdir()
    output = tmp_path / "observation.json"
    node = (
        "tests/unit/test_acquisition.py::test_29_complete_dossiers_are_blocked_not_promoted_by_rows"
    )
    monkeypatch.setenv("FIELDTRUE_CONTROL_ID", "count-intersection")
    monkeypatch.setenv("FIELDTRUE_CONTROL_NODE_ID", node)
    monkeypatch.setenv("FIELDTRUE_CONTROL_OBSERVATION_PATH", str(output))
    candidate_ids = tuple(f"incident-{index:03d}" for index in range(30))
    registry = AcquisitionCandidateRegistry.model_validate(
        {
            "registry_id": "candidate-registry-test",
            "produced_at": "2026-01-01T00:00:00Z",
            "registrar_id": "actor-statistician",
            "candidates": [
                {
                    "incident_id": incident_id,
                    "root_incident_group_id": f"root-{index:03d}",
                    "source_id": "physical-source",
                    "physicality": "physical",
                    "discovered_at": "2026-01-01T00:00:00Z",
                    "discovery_evidence": {
                        "path": f"discovery/{incident_id}.json",
                        "sha256": ZERO_HASH,
                        "bytes": 0,
                        "media_type": "application/json",
                    },
                }
                for index, incident_id in enumerate(candidate_ids)
            ],
            "attestation": {
                "attestation_id": "candidate-registry-attestation",
                "signer_id": "actor-statistician",
                "subject_kind": "candidate_registry",
                "subject_sha256": ZERO_HASH,
                "issued_at": "2026-01-01T00:00:00Z",
                "signer_public_key": ZERO_HASH,
                "attestation_hash": ZERO_HASH,
                "signature": "0" * 128,
            },
        }
    )
    report = _report(
        "BLOCKED_ACQUISITION",
        AcquisitionGateResult(
            gate_id="conjunctive-coverage",
            status="blocked",
            observed={"checks": {"complete_count": False}},
            requirement="conjunction",
            detail="incomplete",
        ),
        eligible_incidents=tuple(f"incident-{index:03d}" for index in range(29)),
        candidate_incidents=candidate_ids,
        candidate_registry_sha256=sha256_value(registry),
    )

    with pytest.raises(ControlAuthorityError, match="count-intersection"):
        record_control_observation(fixture_root, report)

    atomic_write(
        fixture_root / "candidate_registry.json",
        canonical_json_pretty(registry),
    )
    record_control_observation(fixture_root, report)
    assert output.is_file()


def test_lifecycle_rejects_xfail_and_extra_collection() -> None:
    node = "tests/unit/test_acquisition.py::test_complete_conjunctive_pilot_passes"
    xfailed = PytestLifecycle(
        requested_node_id=node,
        collected_node_ids=(node,),
        phases=(PytestPhase(when="call", outcome="passed", was_xfail=True),),
        exit_status=0,
    )
    with pytest.raises(ControlAuthorityError, match="xfailed"):
        _validate_lifecycle(xfailed, node)

    extra = xfailed.model_copy(
        update={
            "collected_node_ids": (node, "tests/unit/test_acquisition.py::test_extra"),
            "phases": (PytestPhase(when="call", outcome="passed", was_xfail=False),),
        }
    )
    with pytest.raises(ControlAuthorityError, match="extra"):
        _validate_lifecycle(extra, node)

    failed_process = xfailed.model_copy(
        update={
            "exit_status": 1,
            "phases": (PytestPhase(when="call", outcome="passed", was_xfail=False),),
        }
    )
    with pytest.raises(ControlAuthorityError, match="exit status 1"):
        _validate_lifecycle(failed_process, node)

    no_phases = xfailed.model_copy(update={"exit_status": 0, "phases": ()})
    with pytest.raises(ControlAuthorityError, match="no lifecycle phases"):
        _validate_lifecycle(no_phases, node)

    duplicate_call = xfailed.model_copy(
        update={
            "exit_status": 0,
            "phases": (
                PytestPhase(when="call", outcome="passed", was_xfail=False),
                PytestPhase(when="call", outcome="passed", was_xfail=False),
            ),
        }
    )
    with pytest.raises(ControlAuthorityError, match="exactly one call phase"):
        _validate_lifecycle(duplicate_call, node)


def test_exception_observation_requires_the_frozen_semantic_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    (fixture / "hypotheses.json").write_text("{}\n")
    output = tmp_path / "exception-observation.json"
    node = "tests/unit/test_acquisition.py::test_known_only_hypothesis_set_is_invalid"
    monkeypatch.setenv("FIELDTRUE_CONTROL_ID", "known-only-hypotheses")
    monkeypatch.setenv("FIELDTRUE_CONTROL_NODE_ID", node)
    monkeypatch.setenv("FIELDTRUE_CONTROL_OBSERVATION_PATH", str(output))

    with pytest.raises(ControlAuthorityError, match="did not demonstrate"):
        record_control_exception(fixture, ValueError("unrelated validation failure"))

    error = ValueError("fewer than two known mechanism hypotheses")
    record_control_exception(fixture, error)
    observation = ControlObservation.model_validate(read_json(output))
    assert observation.observed_verdict == "INVALID"
    assert observation.observed_failure_code == "known-only-hypotheses"


def test_exception_observation_is_noop_without_authority_and_rejects_positive_control(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    (fixture / "artifact").write_bytes(b"bound")
    record_control_exception(fixture, ValueError("ordinary validation failure"))
    assert tuple(fixture.iterdir()) == (fixture / "artifact",)

    node = _CONTROL_REQUIREMENTS["valid-conjunctive-pilot"][0]
    monkeypatch.setenv(observation_plugin._CONTROL_ENV, "valid-conjunctive-pilot")
    monkeypatch.setenv(observation_plugin._NODE_ENV, node)
    monkeypatch.setenv(observation_plugin._OBSERVATION_ENV, str(tmp_path / "observation.json"))
    with pytest.raises(ControlAuthorityError, match="only for INVALID"):
        record_control_exception(fixture, ValueError("not an invalid control"))


def test_observation_rejects_wrong_verdict_and_missing_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    (fixture / "artifact").write_bytes(b"bound")
    node = _CONTROL_REQUIREMENTS["valid-conjunctive-pilot"][0]
    monkeypatch.setenv(observation_plugin._CONTROL_ENV, "valid-conjunctive-pilot")
    monkeypatch.setenv(observation_plugin._NODE_ENV, node)
    monkeypatch.setenv(observation_plugin._OBSERVATION_ENV, str(tmp_path / "observation.json"))

    with pytest.raises(ControlAuthorityError, match="observed BLOCKED_RIGHTS"):
        record_control_observation(fixture, _report("BLOCKED_RIGHTS"))
    with pytest.raises(ControlAuthorityError, match="does not contain one missing gate"):
        observation_plugin._gate(SimpleNamespace(gates=()), "missing")


def test_pytest_plugin_writes_an_exact_lifecycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node = "tests/unit/test_acquisition.py::test_complete_conjunctive_pilot_passes"
    output = tmp_path / "lifecycle.json"
    monkeypatch.setenv("FIELDTRUE_CONTROL_NODE_ID", node)
    monkeypatch.setenv("FIELDTRUE_CONTROL_PYTEST_OUTCOME_PATH", str(output))
    pytest_configure(SimpleNamespace())
    pytest_collection_finish(SimpleNamespace(items=[SimpleNamespace(nodeid=node)]))
    for when in ("setup", "call", "teardown"):
        pytest_runtest_logreport(SimpleNamespace(nodeid=node, when=when, outcome="passed"))
    pytest_sessionfinish(SimpleNamespace(), 0)

    lifecycle = PytestLifecycle.model_validate(read_json(output))
    _validate_lifecycle(lifecycle, node)
    assert lifecycle.collected_node_ids == (node,)


def test_pytest_plugin_is_inert_without_authority_and_rejects_partial_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(observation_plugin, "_PYTEST_REQUESTED_NODE", None)
    monkeypatch.setattr(observation_plugin, "_PYTEST_COLLECTED", [])
    monkeypatch.setattr(observation_plugin, "_PYTEST_PHASES", [])
    monkeypatch.delenv(observation_plugin._NODE_ENV, raising=False)
    monkeypatch.delenv(observation_plugin._OUTCOME_ENV, raising=False)

    pytest_configure(SimpleNamespace())
    pytest_collection_finish(SimpleNamespace(items=[SimpleNamespace(nodeid="untrusted")]))
    pytest_runtest_logreport(SimpleNamespace(nodeid="untrusted", when="call", outcome="failed"))
    pytest_sessionfinish(SimpleNamespace(), 1)
    assert not list(tmp_path.iterdir())

    monkeypatch.setenv(
        observation_plugin._NODE_ENV,
        "tests/unit/test_acquisition.py::test_partial",
    )
    with pytest.raises(ControlAuthorityError, match="environment is incomplete"):
        pytest_configure(SimpleNamespace())


def test_pytest_plugin_ignores_other_nodes_and_requires_output_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node = _CONTROL_REQUIREMENTS["valid-conjunctive-pilot"][0]
    monkeypatch.setattr(observation_plugin, "_PYTEST_REQUESTED_NODE", node)
    monkeypatch.setattr(observation_plugin, "_PYTEST_PHASES", [])
    monkeypatch.delenv(observation_plugin._OUTCOME_ENV, raising=False)

    pytest_runtest_logreport(
        SimpleNamespace(
            nodeid="tests/unit/test_acquisition.py::test_other",
            when="call",
            outcome="passed",
        )
    )
    assert observation_plugin._PYTEST_PHASES == []
    with pytest.raises(ControlAuthorityError, match="output path is missing"):
        pytest_sessionfinish(SimpleNamespace(), 0)


def test_git_binding_detects_working_byte_drift(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "controls@example.invalid")
    _git(repo, "config", "user.name", "Control Test")
    source = repo / "source.py"
    source.write_text("bound = True\n")
    _git(repo, "add", "source.py")
    _git(repo, "commit", "-qm", "bind source")

    commit, tree = _git_identity(repo)
    bound = _git_bound_source(repo, commit, "validator", "source.py")
    assert bound.sha256 == sha256_file(source)
    assert len(tree) == 40
    _assert_clean_repo(repo)

    source.write_text("bound = False\n")
    with pytest.raises(ControlAuthorityError, match="clean repository"):
        _assert_clean_repo(repo)
    with pytest.raises(ControlAuthorityError, match="working bytes differ"):
        _git_bound_source(repo, commit, "validator", "source.py")


def test_missing_signing_key_fails_closed(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / ".local" / "keys").mkdir(parents=True)
    with pytest.raises(ControlAuthorityError, match="cannot be opened"):
        producer._read_existing_key(repo, ZERO_HASH)


def test_git_identifiers_reject_malformed_substitutions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(authority, "_run_git", lambda *_args, **_kwargs: "short")
    with pytest.raises(ControlAuthorityError, match="unsupported object identity"):
        authority._git_identity(tmp_path)
    with pytest.raises(ControlAuthorityError, match="invalid source path"):
        authority._git_bound_source(tmp_path, ZERO_BLOB, "validator", "../escape.py")

    responses = iter((ZERO_BLOB, "tree"))
    monkeypatch.setattr(authority, "_run_git", lambda *_args, **_kwargs: next(responses))
    with pytest.raises(ControlAuthorityError, match="not a Git blob"):
        authority._git_bound_source(tmp_path, ZERO_BLOB, "validator", "source.py")


def test_commit_snapshot_rejects_aggregate_bytes_before_exceeding_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = (
        b"100644 blob object-1\tpyproject.toml\0"
        b"100644 blob object-2\tuv.lock\0"
        b"100644 blob object-3\tsrc/fieldtrue/module.py\0"
    )
    payloads = {
        "object-1": b"123456",
        "object-2": b"abcdef",
        "object-3": b"source",
    }

    def fake_git(_repo: Path, *arguments: str, text: bool = True) -> str | bytes:
        if arguments[0] == "ls-tree":
            assert not text
            return records
        assert arguments[:2] == ("cat-file", "blob")
        assert not text
        return payloads[arguments[2]]

    monkeypatch.setattr(launcher, "_run_git", fake_git)
    monkeypatch.setattr(launcher, "MAX_RUNNER_TREE_BYTES", 10)
    destination = tmp_path / "snapshot"

    assert not launcher._materialize_commit_snapshot(tmp_path, ZERO_BLOB, destination)
    assert destination.joinpath("pyproject.toml").read_bytes() == b"123456"
    assert not destination.joinpath("uv.lock").exists()


def test_fake_ambient_uv_cannot_emit_control_evidence_or_reach_signing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    forged_control = tmp_path / "forged-control.json"
    forged_signature = tmp_path / "forged-signature.txt"
    fake_uv = tmp_path / "uv"
    fake_uv.write_text(
        "#!/bin/sh\n"
        f"printf '{{\"forged\":true}}\\n' > '{forged_control}'\n"
        f"printf 'forged-signature\\n' > '{forged_signature}'\n"
        "printf 'uv 0.11.28 (ebf0f43d7 2026-07-07 aarch64-apple-darwin)\\n'\n"
    )
    fake_uv.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr(launcher, "_clean_head", lambda _repo: (ZERO_BLOB, "1" * 40))

    signing_reached = False

    def reject_signing(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal signing_reached
        signing_reached = True
        raise AssertionError("hostile runner reached signing")

    monkeypatch.setattr(producer, "_read_existing_key", reject_signing)

    def reject_runner(*_args: Any, **_kwargs: Any) -> Any:
        raise ControlAuthorityError("uv acquisition source is untrusted")

    monkeypatch.setattr(launcher, "_prepare_authenticated_runner", reject_runner)
    output = repo / ".local" / "admission-controls"
    with pytest.raises(ControlAuthorityError, match="uv acquisition source"):
        generate_admission_control_bundle(
            repo,
            output,
            repo / CONTROL_PRODUCER_KEY_PATH,
        )

    assert not forged_control.exists()
    assert not forged_signature.exists()
    assert not output.exists()
    assert signing_reached is False


def _positive_observation(node: str) -> ControlObservation:
    report = _report(
        "PASS_PILOT",
        AcquisitionGateResult(
            gate_id="artifact-integrity",
            status="pass",
            observed={"failures": []},
            requirement="integrity",
            detail="complete",
        ),
    )
    report_value = report.model_dump(mode="json")
    file = FixtureFile(path="fixture.json", sha256=ZERO_HASH, bytes=2)
    snapshot = FixtureSnapshot(
        files=(file,),
        root_sha256=sha256_value([file.model_dump(mode="json")]),
    )
    return ControlObservation(
        control_id="valid-conjunctive-pilot",
        pytest_node_id=node,
        fixture=snapshot,
        report_sha256=sha256_value(report_value),
        report=report_value,
        observed_verdict="PASS_PILOT",
        observed_gate_id="admission",
        observed_failure_code=None,
    )


def _test_runner(tmp_path: Path) -> authority.AuthenticatedRunner:
    root = tmp_path / "runner"
    snapshot = root / "snapshot"
    site_packages = root / "authenticated-site-packages"
    interpreter_root = root / "python-install" / "test-python"
    scratch_root = root / "runner-scratch"
    python_path = interpreter_root / "bin" / "python3.12"
    snapshot.mkdir(parents=True)
    site_packages.mkdir()
    python_path.parent.mkdir(parents=True)
    scratch_root.mkdir()
    binding = authority.runner_trust.ExecutableBinding(
        lexical_path=python_path,
        resolved_path=python_path,
        sha256=ZERO_HASH,
        size=1,
        mode=0o500,
        owner_uid=os.getuid(),
        owner_gid=os.getgid(),
    )
    return authority.AuthenticatedRunner(
        root=root,
        snapshot_root=snapshot,
        python_path=python_path,
        site_packages=site_packages,
        interpreter_root=interpreter_root,
        scratch_root=scratch_root,
        uv=authority.runner_trust.PinnedUvBinding(
            executable=binding,
            version="uv test",
            target="test-target",
        ),
        python=binding,
        python_artifact_sha256=ZERO_HASH,
        host_tool=authority.runner_trust.HostToolBinding(
            trust_root="test-host",
            system="test-system",
            machine="test-machine",
            release="test-release",
            version="test-version",
            tool=None,
        ),
        python_version="3.12.13",
        lock_sha256=ZERO_HASH,
        artifact_set_sha256=ZERO_HASH,
        environment_sha256=ZERO_HASH,
        excluded_tree_paths=("runner-scratch",),
        distribution_versions=(("pytest", "test"),),
    )


def _record_spawned_processes(
    monkeypatch: pytest.MonkeyPatch,
) -> list[subprocess.Popen[bytes]]:
    real_popen = authority.subprocess.Popen
    processes: list[subprocess.Popen[bytes]] = []

    def recording_popen(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        process = real_popen(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(authority.subprocess, "Popen", recording_popen)
    return processes


def test_bounded_control_process_preserves_exact_output(tmp_path: Path) -> None:
    expected_stdout = b"control-output\x00\n"
    expected_stderr = b"diagnostic-output\xff\n"
    command = (
        sys.executable,
        "-I",
        "-c",
        (f"import os; os.write(1, {expected_stdout!r}); os.write(2, {expected_stderr!r})"),
    )

    completed = authority._run_bounded_control_process(
        command,
        cwd=tmp_path,
        env=os.environ.copy(),
        timeout_seconds=5,
    )

    assert completed.returncode == 0
    assert completed.stdout == expected_stdout
    assert completed.stderr == expected_stderr


@pytest.mark.parametrize("file_descriptor", [1, 2])
def test_bounded_control_process_reaps_on_stream_overflow(
    file_descriptor: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(authority, "_MAX_CAPTURE_BYTES", 32)
    monkeypatch.setattr(authority, "_MAX_AGGREGATE_CAPTURE_BYTES", 64)
    processes = _record_spawned_processes(monkeypatch)
    command = (
        sys.executable,
        "-I",
        "-c",
        f"import os,time;os.write({file_descriptor}, b'x' * 33);time.sleep(30)",
    )

    with pytest.raises(ControlAuthorityError, match="capture bound"):
        authority._run_bounded_control_process(
            command,
            cwd=tmp_path,
            env=os.environ.copy(),
            timeout_seconds=5,
        )

    assert len(processes) == 1
    assert processes[0].poll() is not None


def test_bounded_control_process_reaps_on_aggregate_overflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(authority, "_MAX_CAPTURE_BYTES", 32)
    monkeypatch.setattr(authority, "_MAX_AGGREGATE_CAPTURE_BYTES", 40)
    processes = _record_spawned_processes(monkeypatch)
    command = (
        sys.executable,
        "-I",
        "-c",
        "import os,time;os.write(1,b'x'*24);os.write(2,b'y'*24);time.sleep(30)",
    )

    with pytest.raises(ControlAuthorityError, match="capture bound"):
        authority._run_bounded_control_process(
            command,
            cwd=tmp_path,
            env=os.environ.copy(),
            timeout_seconds=5,
        )

    assert len(processes) == 1
    assert processes[0].poll() is not None


def test_bounded_control_process_reaps_on_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    processes = _record_spawned_processes(monkeypatch)
    command = (sys.executable, "-I", "-c", "import time;time.sleep(30)")

    with pytest.raises(subprocess.TimeoutExpired):
        authority._run_bounded_control_process(
            command,
            cwd=tmp_path,
            env=os.environ.copy(),
            timeout_seconds=0.1,
        )

    assert len(processes) == 1
    assert processes[0].poll() is not None


def test_bounded_control_process_rejects_and_terminates_descendant_after_success(
    tmp_path: Path,
) -> None:
    descendant_pid_path = tmp_path / "descendant.pid"
    descendant_script = "import os,time;os.close(1);os.close(2);time.sleep(30)"
    leader_script = (
        "import pathlib,subprocess,sys;"
        f"process=subprocess.Popen([sys.executable,'-I','-c',{descendant_script!r}]);"
        "pathlib.Path(sys.argv[1]).write_text(str(process.pid),encoding='ascii')"
    )
    command = (
        sys.executable,
        "-I",
        "-c",
        leader_script,
        str(descendant_pid_path),
    )
    descendant_pid: int | None = None
    descendant_alive = False
    try:
        with pytest.raises(
            ControlAuthorityError,
            match=r"left descendant processes|process-group state cannot be verified",
        ):
            authority._run_bounded_control_process(
                command,
                cwd=tmp_path,
                env=os.environ.copy(),
                timeout_seconds=5,
            )
        descendant_pid = int(descendant_pid_path.read_text(encoding="ascii"))
        try:
            os.kill(descendant_pid, 0)
        except ProcessLookupError:
            pass
        else:
            descendant_alive = True
    finally:
        if descendant_pid is not None and descendant_alive:
            with suppress(ProcessLookupError):
                os.kill(descendant_pid, signal.SIGKILL)

    assert not descendant_alive


def _sidecar_fixture(model_name: str) -> tuple[type[Any], bytes]:
    node = _CONTROL_REQUIREMENTS["valid-conjunctive-pilot"][0]
    if model_name == "lifecycle":
        value = PytestLifecycle(
            requested_node_id=node,
            collected_node_ids=(node,),
            phases=(PytestPhase(when="call", outcome="passed", was_xfail=False),),
            exit_status=0,
        )
        return PytestLifecycle, canonical_json_pretty(value)
    return ControlObservation, canonical_json_pretty(_positive_observation(node))


@pytest.mark.parametrize("model_name", ["lifecycle", "observation"])
@pytest.mark.parametrize("fault", ["oversized", "symlink", "special"])
def test_control_sidecar_rejects_unbounded_or_unsafe_files(
    model_name: str,
    fault: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model, valid_bytes = _sidecar_fixture(model_name)
    path = tmp_path / f"{model_name}.json"
    if fault == "oversized":
        monkeypatch.setattr(authority, "_MAX_CONTROL_SIDECAR_BYTES", len(valid_bytes) - 1)
        path.write_bytes(valid_bytes)
    elif fault == "symlink":
        target = tmp_path / f"{model_name}-target.json"
        target.write_bytes(valid_bytes)
        path.symlink_to(target)
    else:
        if not hasattr(os, "mkfifo"):
            pytest.skip("FIFO creation requires POSIX")
        os.mkfifo(path)

    with pytest.raises(ControlAuthorityError, match="bounded stable regular file"):
        authority._load_control_sidecar(
            path,
            model,
            label=model_name,
            missing_message="sidecar missing",
        )


@pytest.mark.parametrize("model_name", ["lifecycle", "observation"])
def test_control_sidecar_rejects_replacement_between_lstat_and_open(
    model_name: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model, valid_bytes = _sidecar_fixture(model_name)
    path = tmp_path / f"{model_name}.json"
    path.write_bytes(valid_bytes)
    replacement = tmp_path / f"{model_name}-replacement.json"
    replacement.write_bytes(valid_bytes)
    original_open = authority.runner_trust.os.open
    replaced = False

    def racing_open(
        target: str | os.PathLike[str],
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

    monkeypatch.setattr(authority.runner_trust.os, "open", racing_open)

    with pytest.raises(ControlAuthorityError, match="bounded stable regular file"):
        authority._load_control_sidecar(
            path,
            model,
            label=model_name,
            missing_message="sidecar missing",
        )


def test_run_control_requires_both_pytest_and_audit_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    node = "tests/unit/test_acquisition.py::test_complete_conjunctive_pilot_passes"

    def successful_run(
        command: tuple[str, ...], **kwargs: Any
    ) -> subprocess.CompletedProcess[bytes]:
        environment = kwargs["env"]
        observation_path = Path(environment["FIELDTRUE_CONTROL_OBSERVATION_PATH"])
        outcome_path = Path(environment["FIELDTRUE_CONTROL_PYTEST_OUTCOME_PATH"])
        atomic_write(observation_path, canonical_json_pretty(_positive_observation(node)))
        lifecycle = PytestLifecycle(
            requested_node_id=node,
            collected_node_ids=(node,),
            phases=(PytestPhase(when="call", outcome="passed", was_xfail=False),),
            exit_status=0,
        )
        atomic_write(outcome_path, canonical_json_pretty(lifecycle))
        return subprocess.CompletedProcess(command, 0, b"passed\n", b"")

    monkeypatch.setattr(authority, "_run_bounded_control_process", successful_run)
    result, entry = _run_control(
        staging,
        commit=ZERO_BLOB,
        tree="1" * 40,
        control_id="valid-conjunctive-pilot",
        runner=_test_runner(tmp_path),
        timeout_seconds=10,
    )
    assert result.passed is True
    assert entry.evidence.sha256 == sha256_file(staging / entry.evidence.path)

    def lifecycle_only(
        command: tuple[str, ...], **kwargs: Any
    ) -> subprocess.CompletedProcess[bytes]:
        environment = kwargs["env"]
        lifecycle = PytestLifecycle(
            requested_node_id=node,
            collected_node_ids=(node,),
            phases=(PytestPhase(when="call", outcome="passed", was_xfail=False),),
            exit_status=0,
        )
        atomic_write(
            Path(environment["FIELDTRUE_CONTROL_PYTEST_OUTCOME_PATH"]),
            canonical_json_pretty(lifecycle),
        )
        return subprocess.CompletedProcess(command, 0, b"passed\n", b"")

    monkeypatch.setattr(authority, "_run_bounded_control_process", lifecycle_only)
    with pytest.raises(ControlAuthorityError, match="no audit observation"):
        _run_control(
            staging,
            commit=ZERO_BLOB,
            tree="1" * 40,
            control_id="valid-conjunctive-pilot",
            runner=_test_runner(tmp_path / "second"),
            timeout_seconds=10,
        )


@pytest.mark.parametrize(
    ("mode", "message"),
    [
        ("timeout", "timed out"),
        ("oversized", "capture bound"),
        ("no-lifecycle", "no pytest lifecycle"),
        ("process-failure", "process failed"),
        ("wrong-observation", "observation differs"),
    ],
)
def test_run_control_fails_closed_on_process_and_evidence_faults(
    mode: str,
    message: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    node = _CONTROL_REQUIREMENTS["valid-conjunctive-pilot"][0]

    def controlled_run(
        command: tuple[str, ...], **kwargs: Any
    ) -> subprocess.CompletedProcess[bytes]:
        if mode == "timeout":
            raise subprocess.TimeoutExpired(command, 10)
        environment = kwargs["env"]
        if mode == "oversized":
            return subprocess.CompletedProcess(
                command,
                0,
                b"x" * (authority._MAX_CAPTURE_BYTES + 1),
                b"",
            )
        if mode != "no-lifecycle":
            lifecycle = PytestLifecycle(
                requested_node_id=node,
                collected_node_ids=(node,),
                phases=(PytestPhase(when="call", outcome="passed", was_xfail=False),),
                exit_status=0,
            )
            atomic_write(
                Path(environment[observation_plugin._OUTCOME_ENV]),
                canonical_json_pretty(lifecycle),
            )
        if mode == "wrong-observation":
            observation = _positive_observation(node).model_copy(
                update={"observed_gate_id": "substituted-gate"}
            )
            atomic_write(
                Path(environment[observation_plugin._OBSERVATION_ENV]),
                canonical_json_pretty(observation),
            )
        return subprocess.CompletedProcess(
            command,
            1 if mode == "process-failure" else 0,
            b"",
            b"",
        )

    monkeypatch.setattr(authority, "_run_bounded_control_process", controlled_run)
    with pytest.raises(ControlAuthorityError, match=message):
        _run_control(
            staging,
            commit=ZERO_BLOB,
            tree="1" * 40,
            control_id="valid-conjunctive-pilot",
            runner=_test_runner(tmp_path),
            timeout_seconds=10,
        )


def _write_fake_control_result(
    staging: Path,
    control_id: str,
    *,
    commit: str,
    tree: str,
) -> tuple[AdmissionControlResult, authority.ControlManifestEntry]:
    node, verdict, gate, failure = _CONTROL_REQUIREMENTS[control_id]
    report = {"control_id": control_id, "verdict": verdict}
    fixture_file = FixtureFile(
        path=f"fixtures/{control_id}.json",
        sha256=sha256_value({"fixture": control_id}),
        bytes=0,
    )
    fixture = FixtureSnapshot(
        files=(fixture_file,),
        root_sha256=sha256_value([fixture_file.model_dump(mode="json")]),
    )
    observation = ControlObservation(
        control_id=control_id,
        pytest_node_id=node,
        fixture=fixture,
        report_sha256=sha256_value(report),
        report=report,
        observed_verdict=verdict,
        observed_gate_id=gate,
        observed_failure_code=failure,
    )
    lifecycle = PytestLifecycle(
        requested_node_id=node,
        collected_node_ids=(node,),
        phases=(PytestPhase(when="call", outcome="passed", was_xfail=False),),
        exit_status=0,
    )
    execution_evidence = authority.ControlExecutionEvidence(
        execution_commit=commit,
        execution_tree=tree,
        control_id=control_id,
        pytest_node_id=node,
        command=authority._normalized_control_command(node),
        observation=observation,
        lifecycle=lifecycle,
        stdout_sha256=authority.sha256_bytes(b""),
        stderr_sha256=authority.sha256_bytes(b""),
        stdout="",
        stderr="",
    )
    evidence_path = staging / "controls" / f"{control_id}.json"
    atomic_write(evidence_path, canonical_json_pretty(execution_evidence))
    evidence = ArtifactBinding(
        path=evidence_path.relative_to(staging).as_posix(),
        sha256=sha256_file(evidence_path),
        bytes=evidence_path.stat().st_size,
        media_type="application/json",
    )
    result = AdmissionControlResult(
        control_id=control_id,
        fixture_sha256=fixture.root_sha256,
        report_sha256=observation.report_sha256,
        evidence=evidence,
        pytest_node_id=node,
        expected_verdict=verdict,
        observed_verdict=verdict,
        expected_gate_id=gate,
        observed_gate_id=gate,
        expected_failure_code=failure,
        observed_failure_code=failure,
        passed=True,
    )
    entry = authority.ControlManifestEntry(
        control_id=control_id,
        pytest_node_id=node,
        expected_verdict=verdict,
        expected_gate_id=gate,
        expected_failure_code=failure,
        evidence=evidence,
    )
    return result, entry


@pytest.fixture(scope="module")
def generated_bundle(tmp_path_factory: pytest.TempPathFactory) -> SimpleNamespace:
    root = tmp_path_factory.mktemp("control-authority-bundle")
    repo = root / "repo"
    repo.mkdir()
    source_paths = tuple(path for _name, path in authority._SOURCE_PATHS)
    for relative in source_paths:
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"fixture:{relative}\n")
    (repo / ".gitignore").write_text(".local/\n")
    key_path = repo / CONTROL_PRODUCER_KEY_PATH
    key = load_or_create_signing_key(key_path)
    contract = read_json(
        Path(__file__).parents[2] / "protocol" / "acquisition" / "iter001_contract.json"
    )
    contract["authority_profile"] = "test_fixture"
    contract["control_authority_status"] = "test_fixture"
    contract["trust_anchor_public_key"] = key.verify_key.encode().hex()
    contract_path = repo / "protocol" / "acquisition" / "iter001_contract.json"
    contract_path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(contract_path, canonical_json_pretty(contract))
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "controls@example.invalid")
    _git(repo, "config", "user.name", "Control Test")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "freeze authority")
    fixture_commit = str(authority._run_git(repo, "rev-parse", "HEAD"))
    validator_blob = str(authority._run_git(repo, "rev-parse", "HEAD:src/fieldtrue/acquisition.py"))
    validator_sha256 = sha256_file(repo / "src/fieldtrue/acquisition.py")
    fixture_closure = authority._acquisition_source_closure(
        authority.trusted_repository_git(repo),
        repo,
        authority.git_environment(),
        authority_commit=fixture_commit,
        repository_head=fixture_commit,
        expected_validator_blob=validator_blob,
        expected_validator_sha256=validator_sha256,
    )

    def fake_control(
        staging: Path,
        *,
        commit: str,
        tree: str,
        control_id: str,
        runner: authority.AuthenticatedRunner,
        timeout_seconds: int,
    ) -> tuple[AdmissionControlResult, authority.ControlManifestEntry]:
        del runner, timeout_seconds
        return _write_fake_control_result(
            staging,
            control_id,
            commit=commit,
            tree=tree,
        )

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(producer, "_run_control", fake_control)
    monkeypatch.setattr(producer, "_authenticated_runner_is_unchanged", lambda _runner: True)
    monkeypatch.setattr(
        producer,
        "_verify_source_closure",
        lambda _repo, _runner, _commit, _sources: (
            fixture_closure.closure_sha256,
            len(fixture_closure.sources),
        ),
    )
    monkeypatch.setattr(
        producer,
        "_verify_preregistration_ancestry",
        lambda _repo, _contract, _commit: None,
    )
    monkeypatch.setattr(
        producer,
        "_verify_preregistration_bytes",
        lambda _repo, _contract, _commit: None,
    )
    output = repo / ".local" / "admission-controls"
    try:
        receipt_path, _commit, _tree, receipt_sha256 = producer._produce_fixture_bundle(
            repo,
            _test_runner(root),
            expected_commit=fixture_commit,
            expected_tree=str(authority._run_git(repo, "rev-parse", "HEAD^{tree}")),
            timeout_seconds=600,
        )
    finally:
        monkeypatch.undo()
    receipt = AdmissionControlSuiteReceipt.model_validate(read_json(receipt_path))
    assert receipt_sha256 == sha256_file(receipt_path)
    contract["control_suite_sha256"] = sha256_value(receipt)
    contract["validator_git_blob"] = receipt.validator_git_blob
    contract["validator_source_sha256"] = receipt.validator_source_sha256
    contract["dependency_lock_sha256"] = receipt.dependency_lock_sha256
    atomic_write(contract_path, canonical_json_pretty(contract))
    contract_model = AcquisitionContract.model_validate(contract)

    return SimpleNamespace(
        repo=repo,
        output=output,
        key=key,
        key_path=key_path,
        contract_path=contract_path,
        contract_value=contract,
        contract=contract_model,
        receipt=receipt,
    )


def test_generator_signs_only_a_complete_clean_head_bundle(
    generated_bundle: SimpleNamespace,
    tmp_path: Path,
) -> None:
    repo = generated_bundle.repo
    output = generated_bundle.output
    key_path = generated_bundle.key_path
    receipt = generated_bundle.receipt
    contract_model = generated_bundle.contract

    assert tuple(control.control_id for control in receipt.controls) == _REQUIRED_CONTROL_IDS
    assert receipt.attestation.signer_public_key == generated_bundle.key.verify_key.encode().hex()
    assert (output / receipt.execution_manifest.path).is_file()
    verified = verify_admission_control_bundle(repo, output, contract_model)
    assert verified == receipt

    tampered_output = tmp_path / "tampered-output"
    shutil.copytree(output, tampered_output)
    first_evidence = tampered_output / receipt.controls[0].evidence.path
    atomic_write(first_evidence, b"{}\n")
    with pytest.raises(ControlAuthorityError, match="binding mismatch"):
        verify_admission_control_bundle(repo, tampered_output, contract_model)
    with pytest.raises(FileExistsError):
        generate_admission_control_bundle(repo, output, key_path)


def test_v1_control_receipt_is_structurally_fixture_only(
    generated_bundle: SimpleNamespace,
) -> None:
    value = generated_bundle.receipt.model_dump(mode="json")
    value["authority_profile"] = "canonical"
    with pytest.raises(ValueError, match="test_fixture"):
        AdmissionControlSuiteReceipt.model_validate(value)


def test_fixture_receipt_cannot_be_replayed_under_changed_contract_authority(
    generated_bundle: SimpleNamespace,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "replayed-repo"
    shutil.copytree(generated_bundle.repo, repo)
    contract_value = generated_bundle.contract.model_dump(mode="json")
    contract_value["preregistration_commit"] = "f" * 40
    changed_contract = AcquisitionContract.model_validate(contract_value)
    atomic_write(
        repo / "protocol" / "acquisition" / "iter001_contract.json",
        canonical_json_pretty(changed_contract),
    )

    with pytest.raises(ControlAuthorityError, match="differs beyond receipt-derived bindings"):
        verify_admission_control_bundle(
            repo,
            repo / ".local" / "admission-controls",
            changed_contract,
        )


def test_bound_json_rejects_missing_unsafe_tampered_and_non_object_artifacts(
    tmp_path: Path,
) -> None:
    missing = ArtifactBinding(
        path="missing.json",
        sha256=ZERO_HASH,
        bytes=0,
        media_type="application/json",
    )
    with pytest.raises(ControlAuthorityError, match="missing control artifact"):
        authority._read_bound_json(tmp_path, missing)

    target = tmp_path / "target.json"
    atomic_write(target, b"{}\n")
    alias = tmp_path / "alias.json"
    alias.symlink_to(target)
    with pytest.raises(ControlAuthorityError, match="unsafe control artifact"):
        authority._read_bound_json(tmp_path, authority._artifact_binding(tmp_path, alias))

    binding = authority._artifact_binding(tmp_path, target)
    atomic_write(target, b'{"tampered":true}\n')
    with pytest.raises(ControlAuthorityError, match="binding mismatch"):
        authority._read_bound_json(tmp_path, binding)

    invalid = tmp_path / "invalid.json"
    atomic_write(invalid, b"not-json\n")
    with pytest.raises(ControlAuthorityError, match="not JSON"):
        authority._read_bound_json(tmp_path, authority._artifact_binding(tmp_path, invalid))

    sequence = tmp_path / "sequence.json"
    atomic_write(sequence, b"[]\n")
    with pytest.raises(ControlAuthorityError, match="not an object"):
        authority._read_bound_json(tmp_path, authority._artifact_binding(tmp_path, sequence))


def test_verifier_rejects_signature_history_source_and_registry_substitutions(
    generated_bundle: SimpleNamespace,
) -> None:
    receipt = generated_bundle.receipt
    contract = generated_bundle.contract
    manifest = authority.ControlExecutionManifest.model_validate(
        read_json(generated_bundle.output / receipt.execution_manifest.path)
    )

    authority._verify_control_attestation(receipt, contract)
    forged_attestation = receipt.attestation.model_copy(update={"signature": "f" * 128})
    with pytest.raises(ControlAuthorityError, match="signature is invalid"):
        authority._verify_control_attestation(
            receipt.model_copy(update={"attestation": forged_attestation}),
            contract,
        )
    wrong_signer = receipt.attestation.model_copy(update={"signer_id": "substituted-root"})
    with pytest.raises(ControlAuthorityError, match="differs from authority"):
        authority._verify_control_attestation(
            receipt.model_copy(update={"attestation": wrong_signer}),
            contract,
        )

    authority._verify_execution_ancestry(
        generated_bundle.repo,
        receipt.execution_commit,
        receipt.execution_tree,
    )
    with pytest.raises(ControlAuthorityError, match="commit and tree are incoherent"):
        authority._verify_execution_ancestry(
            generated_bundle.repo,
            receipt.execution_commit,
            ZERO_BLOB,
        )
    with pytest.raises(ControlAuthorityError, match="identity does not resolve"):
        authority._verify_execution_ancestry(generated_bundle.repo, ZERO_BLOB, ZERO_BLOB)
    divergent_commit = str(
        authority._run_git(
            generated_bundle.repo,
            "commit-tree",
            receipt.execution_tree,
            "-m",
            "divergent control authority",
        )
    )
    with pytest.raises(ControlAuthorityError, match="not an ancestor"):
        authority._verify_execution_ancestry(
            generated_bundle.repo,
            divergent_commit,
            receipt.execution_tree,
        )

    authority._verify_historical_sources(generated_bundle.repo, receipt, manifest)
    substituted_source = manifest.sources[0].model_copy(update={"sha256": ZERO_HASH})
    substituted_manifest = manifest.model_copy(
        update={"sources": (substituted_source, *manifest.sources[1:])}
    )
    with pytest.raises(ControlAuthorityError, match="source differs"):
        authority._verify_historical_sources(
            generated_bundle.repo,
            receipt,
            substituted_manifest,
        )

    authority._verify_control_evidence(generated_bundle.output, receipt, manifest)
    wrong_manifest_path = receipt.execution_manifest.model_copy(
        update={"path": "substituted-manifest.json"}
    )
    with pytest.raises(ControlAuthorityError, match="path registry is not exact"):
        authority._verify_control_evidence(
            generated_bundle.output,
            receipt.model_copy(update={"execution_manifest": wrong_manifest_path}),
            manifest,
        )
    wrong_entry = manifest.controls[0].model_copy(update={"expected_gate_id": "substituted-gate"})
    with pytest.raises(ControlAuthorityError, match="manifest and receipt result differ"):
        authority._verify_control_evidence(
            generated_bundle.output,
            receipt,
            manifest.model_copy(update={"controls": (wrong_entry, *manifest.controls[1:])}),
        )


def test_historical_source_verifier_rejects_resolution_and_type_faults(
    generated_bundle: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = generated_bundle.receipt
    manifest = authority.ControlExecutionManifest.model_validate(
        read_json(generated_bundle.output / receipt.execution_manifest.path)
    )

    def unresolved(*_args: Any, **_kwargs: Any) -> str:
        raise subprocess.CalledProcessError(1, "git")

    monkeypatch.setattr(authority, "_run_git", unresolved)
    with pytest.raises(ControlAuthorityError, match="source does not resolve"):
        authority._verify_historical_sources(generated_bundle.repo, receipt, manifest)

    responses = iter((ZERO_BLOB, "text-instead-of-bytes"))
    monkeypatch.setattr(authority, "_run_git", lambda *_args, **_kwargs: next(responses))
    with pytest.raises(ControlAuthorityError, match="non-binary"):
        authority._verify_historical_sources(generated_bundle.repo, receipt, manifest)


def test_atomic_publication_maps_no_replace_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.mkdir()

    class RefusingLibc:
        def renameat2(self, *_args: Any) -> int:
            return -1

    descriptor = os.open(tmp_path, os.O_RDONLY)
    try:
        monkeypatch.setattr(producer.sys, "platform", "linux")
        monkeypatch.setattr(producer.ctypes, "CDLL", lambda *_args, **_kwargs: RefusingLibc())
        monkeypatch.setattr(producer.ctypes, "get_errno", lambda: errno.EEXIST)
        with pytest.raises(FileExistsError):
            producer._rename_no_replace_at(descriptor, source.name, target.name)

        monkeypatch.setattr(producer.ctypes, "get_errno", lambda: errno.EACCES)
        with pytest.raises(OSError, match="Permission denied"):
            producer._rename_no_replace_at(descriptor, source.name, target.name)

        monkeypatch.setattr(producer.sys, "platform", "unsupported")
        with pytest.raises(ControlAuthorityError, match="unsupported"):
            producer._rename_no_replace_at(descriptor, source.name, target.name)
    finally:
        os.close(descriptor)


def test_verifier_rejects_non_directory_invalid_receipt_and_noncanonical_contract(
    generated_bundle: SimpleNamespace,
    tmp_path: Path,
) -> None:
    regular_file = tmp_path / "regular-file"
    regular_file.write_bytes(b"not a directory")
    with pytest.raises(ControlAuthorityError, match="requires repository and bundle directories"):
        verify_admission_control_bundle(
            generated_bundle.repo,
            regular_file,
            generated_bundle.contract,
        )

    invalid_bundle = tmp_path / "invalid-bundle"
    invalid_bundle.mkdir()
    atomic_write(invalid_bundle / "control_suite_receipt.json", b"{}\n")
    with pytest.raises(ControlAuthorityError, match="receipt or canonical contract is invalid"):
        verify_admission_control_bundle(
            generated_bundle.repo,
            invalid_bundle,
            generated_bundle.contract,
        )

    noncanonical = generated_bundle.contract.model_copy(update={"control_suite_sha256": ZERO_HASH})
    with pytest.raises(ControlAuthorityError, match="contract is not canonical"):
        verify_admission_control_bundle(
            generated_bundle.repo,
            generated_bundle.output,
            noncanonical,
        )


def test_control_authority_cli_resolves_paths_and_reports_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    captured: dict[str, Any] = {}

    def generate(
        repo: Path,
        output: Path,
        key: Path,
        *,
        timeout_seconds: int,
    ) -> Path:
        captured.update(repo=repo, output=output, key=key, timeout=timeout_seconds)
        return output / "control_suite_receipt.json"

    monkeypatch.setattr(launcher, "generate_admission_control_bundle", generate)
    assert (
        launcher.main(
            [
                "--repo",
                str(tmp_path),
                "--timeout-seconds",
                "9",
            ]
        )
        == 0
    )
    assert captured == {
        "repo": tmp_path,
        "output": tmp_path / ".local" / "admission-controls",
        "key": tmp_path / CONTROL_PRODUCER_KEY_PATH,
        "timeout": 9,
    }
    assert capsys.readouterr().out.strip() == str(
        tmp_path / ".local" / "admission-controls" / "control_suite_receipt.json"
    )

    def fail_generation(*_args: Any, **_kwargs: Any) -> Path:
        raise ControlAuthorityError("deliberate failure")

    monkeypatch.setattr(launcher, "generate_admission_control_bundle", fail_generation)
    with pytest.raises(SystemExit, match="producer failed: deliberate failure"):
        launcher.main(["--repo", str(tmp_path)])
