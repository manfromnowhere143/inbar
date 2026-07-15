from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import fieldtrue.control_authority as authority
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
    ControlObservation,
    FixtureFile,
    FixtureSnapshot,
    PytestLifecycle,
    PytestPhase,
    _assert_clean_repo,
    _git_bound_source,
    _git_identity,
    _run_control,
    _validate_lifecycle,
    generate_admission_control_bundle,
    pytest_collection_finish,
    pytest_configure,
    pytest_runtest_logreport,
    pytest_sessionfinish,
    record_control_exception,
    record_control_observation,
    snapshot_fixture_tree,
    verify_admission_control_bundle,
)
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
        "dependency_mode": "uv-offline-frozen",
        "uv_executable": "/absolute/uv",
        "uv_executable_sha256": ZERO_HASH,
        "uv_version": "uv 1.0.0",
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
        authority._CONTROL_ENV,
        authority._NODE_ENV,
        authority._OBSERVATION_ENV,
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(authority._CONTROL_ENV, "valid-conjunctive-pilot")
    with pytest.raises(ControlAuthorityError, match="environment is incomplete"):
        authority._control_environment()

    monkeypatch.setenv(authority._NODE_ENV, "tests/unit/test_acquisition.py::test_substituted")
    monkeypatch.setenv(authority._OBSERVATION_ENV, str(tmp_path / "observation.json"))
    with pytest.raises(ControlAuthorityError, match="node differs"):
        authority._control_environment()

    monkeypatch.setenv(authority._CONTROL_ENV, "unknown-control")
    with pytest.raises(ControlAuthorityError, match="unknown admission control"):
        authority._control_environment()


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

    monkeypatch.setattr(authority.subprocess, "run", successful_run)
    result, entry = _run_control(
        tmp_path,
        staging,
        commit=ZERO_BLOB,
        tree="1" * 40,
        control_id="valid-conjunctive-pilot",
        uv_executable="/absolute/uv",
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

    monkeypatch.setattr(authority.subprocess, "run", lifecycle_only)
    with pytest.raises(ControlAuthorityError, match="no audit observation"):
        _run_control(
            tmp_path,
            staging,
            commit=ZERO_BLOB,
            tree="1" * 40,
            control_id="valid-conjunctive-pilot",
            uv_executable="/absolute/uv",
            timeout_seconds=10,
        )


def _write_fake_control_result(
    staging: Path,
    control_id: str,
    *,
    commit: str,
    tree: str,
    uv_executable: str,
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
        command=(
            uv_executable,
            "run",
            "--offline",
            "--frozen",
            "python",
            "-m",
            "pytest",
            "-p",
            "fieldtrue.control_authority",
            "--no-header",
            "--tb=short",
            node,
        ),
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


def test_generator_signs_only_a_complete_clean_head_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    source_paths = (
        "src/fieldtrue/acquisition.py",
        "src/fieldtrue/control_authority.py",
        "tests/acquisition_helpers.py",
        "tests/unit/test_acquisition.py",
        "uv.lock",
    )
    for relative in source_paths:
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"fixture:{relative}\n")
    (repo / ".gitignore").write_text(".local/\n")
    key_path = repo / ".local" / "keys" / "iter001-governance.ed25519"
    key = load_or_create_signing_key(key_path)
    contract = read_json(
        Path(__file__).parents[2] / "protocol" / "acquisition" / "iter001_contract.json"
    )
    contract["authority_profile"] = "test_fixture"
    contract["control_authority_status"] = "test_fixture"
    contract["trust_anchor_public_key"] = key.verify_key.encode().hex()
    contract_path = repo / "protocol" / "acquisition" / "iter001_contract.json"
    contract_path.parent.mkdir(parents=True)
    atomic_write(contract_path, canonical_json_pretty(contract))
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "controls@example.invalid")
    _git(repo, "config", "user.name", "Control Test")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "freeze authority")

    def fake_control(
        repo: Path,
        staging: Path,
        *,
        commit: str,
        tree: str,
        control_id: str,
        uv_executable: str,
        timeout_seconds: int,
    ) -> tuple[AdmissionControlResult, authority.ControlManifestEntry]:
        del repo, timeout_seconds
        return _write_fake_control_result(
            staging,
            control_id,
            commit=commit,
            tree=tree,
            uv_executable=uv_executable,
        )

    true_executable = shutil.which("true")
    assert true_executable is not None
    monkeypatch.setattr(authority, "_run_control", fake_control)
    monkeypatch.setattr(authority, "_resolve_uv_executable", lambda: true_executable)
    monkeypatch.setattr(authority, "_uv_version", lambda _executable: "uv test")
    output = repo / ".local" / "admission-controls"

    receipt_path = generate_admission_control_bundle(repo, output, key_path)
    receipt = AdmissionControlSuiteReceipt.model_validate(read_json(receipt_path))

    assert tuple(control.control_id for control in receipt.controls) == _REQUIRED_CONTROL_IDS
    assert receipt.attestation.signer_public_key == key.verify_key.encode().hex()
    assert (output / receipt.execution_manifest.path).is_file()
    contract["control_suite_sha256"] = sha256_value(receipt)
    contract["validator_git_blob"] = receipt.validator_git_blob
    contract["validator_source_sha256"] = receipt.validator_source_sha256
    contract["dependency_lock_sha256"] = receipt.dependency_lock_sha256
    atomic_write(contract_path, canonical_json_pretty(contract))
    contract_model = AcquisitionContract.model_validate(contract)
    verified = verify_admission_control_bundle(repo, output, contract_model)
    assert verified == receipt

    first_evidence = output / receipt.controls[0].evidence.path
    atomic_write(first_evidence, b"{}\n")
    with pytest.raises(ControlAuthorityError, match="binding mismatch"):
        verify_admission_control_bundle(repo, output, contract_model)
    with pytest.raises(FileExistsError):
        generate_admission_control_bundle(repo, output, key_path)
