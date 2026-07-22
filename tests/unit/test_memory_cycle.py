"""Controls for the receipt, ledger, and handoff cycle producer.

The cycle writes to an append-only hash-chained ledger and creates the exact two-commit
topology the handoff checker demands. A producer that could corrupt the chain, launder a
failing receipt, or smuggle a third file into the final commit would be worse than no
producer at all.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from fieldtrue.canonical import sha256_value
from fieldtrue.domain import (
    EngineeringValidationArtifact,
    EngineeringValidationEnvironment,
    EngineeringValidationMissionObservation,
    EngineeringValidationPytestObservation,
    EngineeringValidationReceipt,
    EngineeringValidationResourceAccounting,
    EngineeringValidationStep,
    engineering_validation_plan_sha256,
)
from fieldtrue.handoff import RECOVERY_CHECKPOINT_ACTION
from fieldtrue.memory_cycle import (
    _EVIDENCE_CORRECTIONS,
    _V28_SCOPE_CORRECTION,
    MemoryCycleError,
    _CheckpointScopeCorrectionSpec,
    _EvidenceCorrectionSpec,
    _git_is_ancestor,
    _load_ledger,
    _v28_scope_correction_is_required,
    produce_handoff_cycle,
)

RECEIPT_ID = "inbar-core-validation-cycle-test"
NOW = datetime(2026, 7, 18, 12, 0, 0, tzinfo=UTC)


def test_evidence_correction_set_binds_every_superseded_checkpoint_summary() -> None:
    repo = Path(__file__).resolve().parents[2]
    records = [
        json.loads(line)
        for line in (repo / "memory/research_engine_extraction.jsonl").read_text().splitlines()
    ]
    by_id = {record["event_id"]: record for record in records}

    assert [item.target_event_id for item in _EVIDENCE_CORRECTIONS] == [
        "inbar-core-validation-checkpoint-v12",
        "inbar-core-validation-checkpoint-v15",
        "inbar-core-validation-checkpoint-v16",
        "inbar-core-validation-checkpoint-v17",
        "inbar-core-validation-checkpoint-v18",
    ]
    for item in _EVIDENCE_CORRECTIONS:
        assert by_id[item.target_event_id]["summary"] == item.old
        assert item.corrected != item.old
        for uri, _media_type, _role in item.evidence:
            assert (repo / uri).is_file()

    assert "no active confirmatory, physical, or recovery status" in (
        _EVIDENCE_CORRECTIONS[1].corrected
    )
    assert "169-of-175 susceptibility observation remains unreconstructed" in (
        _EVIDENCE_CORRECTIONS[2].corrected
    )
    assert "not a first scientific result" in _EVIDENCE_CORRECTIONS[3].corrected


def test_v28_scope_correction_binds_the_exact_checkpoint_and_evidence() -> None:
    repo = Path(__file__).resolve().parents[2]
    records = [
        json.loads(line)
        for line in (repo / "memory/research_engine_extraction.jsonl").read_text().splitlines()
    ]
    by_id = {record["event_id"]: record for record in records}

    target = by_id[_V28_SCOPE_CORRECTION.target_event_id]
    predecessor = by_id[_V28_SCOPE_CORRECTION.predecessor_handoff_id]
    assert target["summary"] == _V28_SCOPE_CORRECTION.old
    assert target["event_hash"] == _V28_SCOPE_CORRECTION.target_event_hash
    assert target["source_commit"] == _V28_SCOPE_CORRECTION.target_source_commit
    assert target["sequence"] == _V28_SCOPE_CORRECTION.target_sequence == 256
    assert predecessor["event_id"] == "inbar-core-validation-handoff-v29"
    assert predecessor["event_hash"] == _V28_SCOPE_CORRECTION.predecessor_handoff_hash
    assert predecessor["source_commit"] == _V28_SCOPE_CORRECTION.predecessor_handoff_source_commit
    assert predecessor["sequence"] == _V28_SCOPE_CORRECTION.predecessor_handoff_sequence == 261
    pretransition = records[: predecessor["sequence"] + 1]
    assert pretransition[-1] == predecessor
    assert [record["sequence"] for record in pretransition] == list(range(len(pretransition)))
    assert _V28_SCOPE_CORRECTION.event_id.endswith("-v30")
    assert _V28_SCOPE_CORRECTION.event_id not in {record["event_id"] for record in pretransition}
    assert by_id[_V28_SCOPE_CORRECTION.event_id]["corrects_event_id"] == target["event_id"]
    assert _V28_SCOPE_CORRECTION.corrected == (
        "Checkpoint v28's separation of acquisition from integrity failures was incomplete. It "
        "did not validate redirect authority before every hop or preserve the acquisition type "
        "across the isolated producer IPC boundary. It also deferred downloaded-body length and "
        "digest classification until after response teardown, so a teardown failure could "
        "replace the primary acquisition or trust error. Those three omissions made its "
        "mechanism scope incomplete; fail-closed execution and the blocked authority boundary "
        "remained in force."
    )
    assert _V28_SCOPE_CORRECTION.evidence == (
        ("src/fieldtrue/runner_trust.py", "text/x-python", "source"),
        ("src/fieldtrue/control_protocol.py", "text/x-python", "source"),
        ("src/fieldtrue/control_producer.py", "text/x-python", "source"),
        ("src/fieldtrue/control_launcher.py", "text/x-python", "source"),
        ("tests/unit/test_runner_trust.py", "text/x-python", "verifier"),
        ("tests/unit/test_control_producer.py", "text/x-python", "verifier"),
    )
    assert _V28_SCOPE_CORRECTION.evidence_sha256 == tuple(
        hashlib.sha256((repo / uri).read_bytes()).hexdigest()
        for uri, _media_type, _role in _V28_SCOPE_CORRECTION.evidence
    )
    for uri, _media_type, _role in _V28_SCOPE_CORRECTION.evidence:
        assert (repo / uri).is_file()


def _git(root: Path, *args: str) -> str:
    return subprocess.run(  # noqa: S603 - fixed trusted Git path, fixed argv
        ["/usr/bin/git", *args], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()


def _seed_repo(root: Path) -> None:
    for args in (
        ("init", "-q"),
        ("config", "user.email", "t@example.invalid"),
        ("config", "user.name", "t"),
    ):
        _git(root, *args)
    (root / "src/fieldtrue").mkdir(parents=True)
    (root / "src/fieldtrue/handoff.py").write_text("# renderer source\n", encoding="utf-8")
    (root / "CONTINUITY.md").write_text("continuity\n", encoding="utf-8")
    (root / "HANDOFF.md").write_text("# stale handoff\n", encoding="utf-8")
    (root / "memory").mkdir()
    previous_body: dict[str, Any] = {
        "access": "internal",
        "actor": {"actor_id": "codex", "kind": "agent"},
        "corrects_event_id": None,
        "cost_usd": "0",
        "engine_requirement": None,
        "epistemic_phase": "retrospective",
        "event_id": "seed-handoff-v1",
        "event_type": "handoff",
        "evidence": [],
        "links": {},
        "manual_minutes": 0.0,
        "mission_id": "inbar",
        "occurred_at": "2026-07-16T00:00:00Z",
        "payload": {
            "handoff_contract": "inbar.handoff-state.v1",
            "next_action": "Complete and prospectively seal iter001-acquisition-contract.",
            "state": "Inbar remains in bootstrap.",
        },
        "previous_event_hash": "0" * 64,
        "recorded_at": "2026-07-16T00:00:00Z",
        "recurrence_key": None,
        "schema_version": "daniel.research-memory.v2",
        "sequence": 2,
        "source_commit": "0" * 40,
        "stage": "mission-handoff",
        "status": "blocked",
        "summary": "Seed handoff state.",
    }
    genesis_body = dict(previous_body)
    genesis_body.update(
        {
            "event_id": "iter001-public-substrate-verdict-v1",
            "event_type": "finding",
            "status": "negative",
            "sequence": 0,
            "payload": {"finding": "BLOCK_CURRENT_PUBLIC_SOURCE_ONLY_ROUTE"},
            "summary": "The legacy public-source route is blocked.",
        }
    )
    genesis_body["event_hash"] = sha256_value(
        {k: v for k, v in genesis_body.items() if k != "event_hash"}
    )
    verdict_body = dict(previous_body)
    verdict_body.update(
        {
            "event_id": "seed-source-verdict-v1",
            "event_type": "finding",
            "status": "negative",
            "sequence": 1,
            "previous_event_hash": genesis_body["event_hash"],
            "links": {"scope_correction": "iter001-public-substrate-verdict-v1"},
            "payload": {"finding": "BLOCK_CURRENT_PUBLIC_SOURCE_ONLY_ROUTE"},
            "summary": "The current protocol blocks the present public-source-only route.",
        }
    )
    verdict_body["event_hash"] = sha256_value(
        {k: v for k, v in verdict_body.items() if k != "event_hash"}
    )
    previous_body["previous_event_hash"] = verdict_body["event_hash"]
    previous_body["event_hash"] = sha256_value(
        {k: v for k, v in previous_body.items() if k != "event_hash"}
    )
    (root / "memory/research_engine_extraction.jsonl").write_text(
        json.dumps(genesis_body, sort_keys=True, separators=(",", ":"))
        + "\n"
        + json.dumps(verdict_body, sort_keys=True, separators=(",", ":"))
        + "\n"
        + json.dumps(previous_body, sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="utf-8",
    )
    (root / "docs/research").mkdir(parents=True)
    (root / "docs/research/ITER001_SOURCE_ROLE_AUDIT.md").write_text("# audit\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "seed")


def _seed_scope_correction_spec(
    root: Path,
    *,
    old: str = "The current protocol blocks the present public-source-only route.",
) -> _CheckpointScopeCorrectionSpec:
    events = [
        json.loads(line)
        for line in (root / "memory/research_engine_extraction.jsonl").read_text().splitlines()
    ]
    target = next(event for event in events if event["event_id"] == "seed-source-verdict-v1")
    predecessor_handoff = next(
        event for event in reversed(events) if event["event_type"] == "handoff"
    )
    predecessor_commit = _git(root, "rev-parse", "HEAD")
    _git(root, "commit", "--allow-empty", "-qm", "scope-correction implementation candidate")
    return _CheckpointScopeCorrectionSpec(
        event_id="cycle-test-v28-scope-correction-v1",
        target_event_id="seed-source-verdict-v1",
        target_event_hash=target["event_hash"],
        target_source_commit=target["source_commit"],
        target_sequence=target["sequence"],
        target_event_type=target["event_type"],
        target_status=target["status"],
        predecessor_handoff_id=predecessor_handoff["event_id"],
        predecessor_handoff_hash=predecessor_handoff["event_hash"],
        predecessor_handoff_source_commit=predecessor_handoff["source_commit"],
        predecessor_handoff_sequence=predecessor_handoff["sequence"],
        predecessor_final_commit=predecessor_commit,
        receipt_id=RECEIPT_ID,
        source_event_id="cycle-test-source-verdict-v1",
        resource_event_id="cycle-test-resource-v1",
        checkpoint_event_id="cycle-test-checkpoint-v1",
        handoff_event_id="cycle-test-handoff-v1",
        old=old,
        corrected="The earlier mechanism statement was incomplete.",
        evidence=(("docs/research/ITER001_SOURCE_ROLE_AUDIT.md", "text/markdown", "source"),),
        evidence_sha256=(
            hashlib.sha256(
                (root / "docs/research/ITER001_SOURCE_ROLE_AUDIT.md").read_bytes()
            ).hexdigest(),
        ),
    )


def _receipt(subject_commit: str, *, result: str = "pass") -> EngineeringValidationReceipt:
    def artifact(name: str) -> EngineeringValidationArtifact:
        return EngineeringValidationArtifact(
            path=f"evidence/validation/{RECEIPT_ID}/{name}",
            sha256=sha256_value(name),
            bytes=1,
            media_type="text/plain; charset=utf-8",
        )

    steps = tuple(
        EngineeringValidationStep(
            step_id=step_id,
            argv=("uv", "run", step_id),
            working_directory=".",
            started_at=NOW,
            finished_at=NOW,
            duration_ms=1,
            expected_exit_code=0,
            observed_exit_code=0 if result == "pass" else 1,
            result="pass" if result == "pass" else "fail",
            stdout=artifact(f"{step_id}.stdout.txt"),
            stderr=artifact(f"{step_id}.stderr.txt"),
        )
        for step_id in ("uv-lock-check", "mission-validate", "pytest-cov")
    )
    return EngineeringValidationReceipt(
        schema_version="inbar.engineering-validation-receipt.v1",
        receipt_id=RECEIPT_ID,
        mission_id="inbar",
        subject_commit=subject_commit,
        subject_tree="a" * 40,
        plan_id="inbar.core-engineering-validation.v1",
        plan_sha256=engineering_validation_plan_sha256(steps),
        started_at=NOW,
        finished_at=NOW,
        producer_actor_id="claude",
        assurance_scope="same-operator-engineering-observation-no-independent-attestation",
        independent_attestation=False,
        environment=EngineeringValidationEnvironment(
            platform="test", machine="test", python_version="3.12", uv_version="0.11.28"
        ),
        steps=steps,
        pytest_observation=EngineeringValidationPytestObservation(
            step_id="pytest-cov",
            junit_xml=artifact("pytest.junit.xml"),
            coverage_json=artifact("coverage.json"),
            tests_passed=100,
            tests_failed=0,
            tests_errors=0,
            tests_skipped=0,
            covered_lines=95,
            num_statements=100,
            covered_branches=10,
            num_branches=10,
        ),
        mission_observation=EngineeringValidationMissionObservation(
            step_id="mission-validate",
            mission_check_ids=("iter001-acquisition-contract", "schemas"),
            expected_blockers=("iter001-acquisition-contract",),
            observed_blockers=("iter001-acquisition-contract",),
            missing_expected_blockers=(),
            unexpected_blockers=(),
        ),
        resource_accounting=EngineeringValidationResourceAccounting(
            measurement_status="not_metered",
            direct_cost_usd=None,
            gpu_seconds=None,
            cloud_jobs=None,
            paid_calls=None,
        ),
        scientific_result="not_evaluated",
        authority_effect="none",
        result="pass" if result == "pass" else "fail",
    )


def _install_stubs(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    receipt_result: str = "pass",
    subject_override: str | None = None,
    render_writes_handoff: bool = True,
    exercise_v28_scope: bool = False,
) -> list[list[str]]:
    calls: list[list[str]] = []

    def fake_receipt(repo_root: Path, *, receipt_id: str, producer_actor_id: str) -> Path:
        subject = subject_override or _git(root, "rev-parse", "HEAD")
        receipt = _receipt(subject, result=receipt_result)
        path = repo_root / f"evidence/validation/{receipt_id}/receipt.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(receipt.model_dump_json(), encoding="utf-8")
        return path

    def fake_inbar(repo_root: Path, *args: str) -> str:
        calls.append(list(args))
        if args == ("handoff", "render") and render_writes_handoff:
            (repo_root / "HANDOFF.md").write_text("# rendered\n", encoding="utf-8")
        return ""

    monkeypatch.setattr("fieldtrue.memory_cycle.write_validation_receipt", fake_receipt)
    monkeypatch.setattr("fieldtrue.memory_cycle._run_inbar", fake_inbar)
    monkeypatch.setattr(
        "fieldtrue.memory_cycle._ENGINE_BOUNDARY_EVENT",
        "iter001-public-substrate-verdict-v1",
    )
    if not exercise_v28_scope:
        monkeypatch.setattr(
            "fieldtrue.memory_cycle._v28_scope_correction_is_required",
            lambda *_args, **_kwargs: False,
        )
    return calls


def _cycle(
    root: Path,
    *,
    receipt_id: str = RECEIPT_ID,
    evidence_correction_event_ids: tuple[str, ...] = (),
    v28_scope_correction_event_id: str | None = None,
) -> dict[str, str]:
    return produce_handoff_cycle(
        root,
        receipt_id=receipt_id,
        producer_actor_id="claude",
        summary="Recorded the census implementation checkpoint.",
        checkpoint_event_id="cycle-test-checkpoint-v1",
        handoff_event_id="cycle-test-handoff-v1",
        resource_event_id="cycle-test-resource-v1",
        source_verdict_event_id="cycle-test-source-verdict-v1",
        evidence_correction_event_ids=evidence_correction_event_ids,
        v28_scope_correction_event_id=v28_scope_correction_event_id,
    )


def test_cycle_produces_the_exact_two_commit_topology(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_repo(tmp_path)
    implementation = _git(tmp_path, "rev-parse", "HEAD")
    calls = _install_stubs(tmp_path, monkeypatch)
    result = _cycle(tmp_path)

    assert result["implementation_commit"] == implementation
    assert _git(tmp_path, "rev-parse", f"{result['evidence_commit']}^") == implementation
    assert _git(tmp_path, "rev-parse", f"{result['final_commit']}^") == result["evidence_commit"]
    final_files = _git(
        tmp_path, "diff", "--name-only", result["evidence_commit"], result["final_commit"]
    ).splitlines()
    assert sorted(final_files) == ["HANDOFF.md", "memory/research_engine_extraction.jsonl"]
    assert ["memory", "verify"] in calls
    assert ["handoff", "render"] in calls
    assert ["handoff", "check"] in calls


def test_cycle_appends_a_verifiable_hash_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_repo(tmp_path)
    _install_stubs(tmp_path, monkeypatch)
    result = _cycle(tmp_path)

    lines = (tmp_path / "memory/research_engine_extraction.jsonl").read_text().splitlines()
    events = [json.loads(line) for line in lines]
    assert [event["sequence"] for event in events] == list(range(7))
    for previous, current in itertools.pairwise(events):
        assert current["previous_event_hash"] == previous["event_hash"]
        body = {k: v for k, v in current.items() if k != "event_hash"}
        assert sha256_value(body) == current["event_hash"]
    verdict, resource, checkpoint, handoff = events[3], events[4], events[5], events[6]
    assert verdict["event_type"] == "finding"
    assert verdict["source_commit"] == result["implementation_commit"]
    # The verdict did not change, so its frozen payload and summary carry forward verbatim.
    assert verdict["payload"] == events[1]["payload"]
    assert verdict["summary"] == events[1]["summary"]
    assert verdict["evidence"][0]["uri"] == "docs/research/ITER001_SOURCE_ROLE_AUDIT.md"
    assert verdict["evidence"][0]["git_commit"] == result["implementation_commit"]
    assert resource["event_type"] == "resource"
    assert checkpoint["payload"]["implementation_commit"] == result["implementation_commit"]
    assert checkpoint["payload"]["validation_receipt"]["receipt_id"] == RECEIPT_ID
    # The renderer requires the checkpoint and handoff events to bind the implementation
    # commit while the resource event binds the evidence commit.
    assert checkpoint["source_commit"] == result["implementation_commit"]
    assert handoff["source_commit"] == result["implementation_commit"]
    assert resource["source_commit"] == result["evidence_commit"]
    # The recovery pair is a frozen contract: the payload text must be the renderer's own.
    assert checkpoint["payload"]["action"] == RECOVERY_CHECKPOINT_ACTION
    assert handoff["links"]["engine_boundary"] == "iter001-public-substrate-verdict-v1"
    assert handoff["evidence"][0]["git_commit"] == result["implementation_commit"]
    assert checkpoint["links"]["resource_observation"] == "cycle-test-resource-v1"
    assert handoff["links"]["checkpoint"] == "cycle-test-checkpoint-v1"
    assert handoff["links"]["source_verdict"] == "cycle-test-source-verdict-v1"
    # The mission state did not change, so the handoff payload carries forward verbatim.
    assert handoff["payload"] == events[2]["payload"]


def test_cycle_appends_explicit_evidence_correction_links(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_repo(tmp_path)
    _install_stubs(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "fieldtrue.memory_cycle._EVIDENCE_CORRECTIONS",
        (
            _EvidenceCorrectionSpec(
                target_event_id="seed-source-verdict-v1",
                old="The current protocol blocks the present public-source-only route.",
                corrected="The bounded correction remains in force.",
                evidence=(
                    (
                        "docs/research/ITER001_SOURCE_ROLE_AUDIT.md",
                        "text/markdown",
                        "source",
                    ),
                ),
            ),
        ),
    )
    result = _cycle(
        tmp_path,
        evidence_correction_event_ids=("cycle-test-evidence-correction-v1",),
    )

    events = [
        json.loads(line)
        for line in (tmp_path / "memory/research_engine_extraction.jsonl").read_text().splitlines()
    ]
    correction = events[4]
    assert correction["event_type"] == "correction"
    assert correction["corrects_event_id"] == "seed-source-verdict-v1"
    assert correction["payload"]["old"] == events[1]["summary"]
    assert correction["payload"]["corrected"] == "The bounded correction remains in force."
    assert correction["source_commit"] == result["implementation_commit"]
    assert correction["evidence"][0]["git_commit"] == result["implementation_commit"]
    assert events[5]["previous_event_hash"] == correction["event_hash"]


def test_cycle_rejects_an_incomplete_evidence_correction_id_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_repo(tmp_path)
    _install_stubs(tmp_path, monkeypatch)
    with pytest.raises(MemoryCycleError, match="do not match"):
        _cycle(tmp_path, evidence_correction_event_ids=("only-one",))


def test_cycle_appends_the_explicit_v28_scope_correction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_repo(tmp_path)
    _install_stubs(tmp_path, monkeypatch, exercise_v28_scope=True)
    monkeypatch.setattr(
        "fieldtrue.memory_cycle._V28_SCOPE_CORRECTION",
        _seed_scope_correction_spec(tmp_path),
    )

    result = _cycle(
        tmp_path,
        v28_scope_correction_event_id="cycle-test-v28-scope-correction-v1",
    )
    events = [
        json.loads(line)
        for line in (tmp_path / "memory/research_engine_extraction.jsonl").read_text().splitlines()
    ]
    correction = events[4]

    assert correction["event_type"] == "correction"
    assert correction["corrects_event_id"] == "seed-source-verdict-v1"
    assert correction["payload"]["authority_effect"] == "none"
    assert correction["source_commit"] == result["implementation_commit"]
    assert correction["evidence"] == [
        {
            "access": "internal",
            "git_commit": result["implementation_commit"],
            "label_access": "none",
            "media_type": "text/markdown",
            "role": "source",
            "sha256": hashlib.sha256(
                (tmp_path / "docs/research/ITER001_SOURCE_ROLE_AUDIT.md").read_bytes()
            ).hexdigest(),
            "uri": "docs/research/ITER001_SOURCE_ROLE_AUDIT.md",
        }
    ]
    assert events[5]["previous_event_hash"] == correction["event_hash"]


def test_cycle_requires_the_v28_scope_correction_before_writing_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_repo(tmp_path)
    _install_stubs(tmp_path, monkeypatch, exercise_v28_scope=True)
    monkeypatch.setattr(
        "fieldtrue.memory_cycle._V28_SCOPE_CORRECTION",
        _seed_scope_correction_spec(tmp_path),
    )
    head = _git(tmp_path, "rev-parse", "HEAD")

    with pytest.raises(MemoryCycleError, match="event ID is required"):
        _cycle(tmp_path)

    assert _git(tmp_path, "rev-parse", "HEAD") == head
    assert _git(tmp_path, "status", "--porcelain") == ""


def test_cycle_requires_the_exact_prospective_v30_ids_before_writing_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _seed_repo(tmp_path)
    _install_stubs(tmp_path, monkeypatch, exercise_v28_scope=True)
    monkeypatch.setattr(
        "fieldtrue.memory_cycle._V28_SCOPE_CORRECTION",
        _seed_scope_correction_spec(tmp_path),
    )
    head = _git(tmp_path, "rev-parse", "HEAD")

    with pytest.raises(MemoryCycleError, match="prospective v30 scope-correction cycle IDs"):
        _cycle(
            tmp_path,
            receipt_id="cycle-test-wrong-receipt",
            v28_scope_correction_event_id="cycle-test-v28-scope-correction-v1",
        )

    assert _git(tmp_path, "rev-parse", "HEAD") == head
    assert _git(tmp_path, "status", "--porcelain") == ""
    assert not (tmp_path / "evidence").exists()


def test_v28_scope_preflight_rejects_a_missing_frozen_target_without_writing_evidence(
    tmp_path: Path,
) -> None:
    _seed_repo(tmp_path)
    head = _git(tmp_path, "rev-parse", "HEAD")

    with pytest.raises(MemoryCycleError, match="scope-correction target differs"):
        _v28_scope_correction_is_required(
            tmp_path,
            _load_ledger(tmp_path),
            event_id=None,
        )

    assert _git(tmp_path, "rev-parse", "HEAD") == head
    assert _git(tmp_path, "status", "--porcelain") == ""
    assert not (tmp_path / "evidence").exists()


def test_v28_scope_preflight_rejects_a_wrong_frozen_predecessor_without_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _seed_repo(tmp_path)
    correction = _seed_scope_correction_spec(tmp_path)
    monkeypatch.setattr("fieldtrue.memory_cycle._V28_SCOPE_CORRECTION", correction)
    ledger = _load_ledger(tmp_path)
    predecessor = next(
        event for event in ledger if event["event_id"] == correction.predecessor_handoff_id
    )
    predecessor["source_commit"] = "f" * 40
    head = _git(tmp_path, "rev-parse", "HEAD")

    with pytest.raises(MemoryCycleError, match="predecessor handoff differs"):
        _v28_scope_correction_is_required(tmp_path, ledger, event_id=correction.event_id)

    assert _git(tmp_path, "rev-parse", "HEAD") == head
    assert not (tmp_path / "evidence").exists()


def test_v28_scope_preflight_rejects_a_skipped_correction_without_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _seed_repo(tmp_path)
    correction = _seed_scope_correction_spec(tmp_path)
    monkeypatch.setattr("fieldtrue.memory_cycle._V28_SCOPE_CORRECTION", correction)
    ledger = _load_ledger(tmp_path)
    skipped = dict(ledger[-1])
    skipped["event_id"] = "cycle-test-unscoped-successor-handoff"
    skipped["sequence"] += 1
    ledger.append(skipped)
    head = _git(tmp_path, "rev-parse", "HEAD")

    with pytest.raises(MemoryCycleError, match="frozen v29 pre-correction"):
        _v28_scope_correction_is_required(tmp_path, ledger, event_id=correction.event_id)

    assert _git(tmp_path, "rev-parse", "HEAD") == head
    assert not (tmp_path / "evidence").exists()


def test_v28_scope_preflight_rejects_a_prospective_event_id_collision_without_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _seed_repo(tmp_path)
    correction = _seed_scope_correction_spec(tmp_path)
    monkeypatch.setattr("fieldtrue.memory_cycle._V28_SCOPE_CORRECTION", correction)
    ledger = _load_ledger(tmp_path)
    collision = dict(ledger[-1])
    collision.update(
        {
            "corrects_event_id": None,
            "event_id": correction.event_id,
            "sequence": collision["sequence"] + 1,
        }
    )
    ledger.append(collision)
    head = _git(tmp_path, "rev-parse", "HEAD")

    with pytest.raises(MemoryCycleError, match="event ID collides"):
        _v28_scope_correction_is_required(tmp_path, ledger, event_id=correction.event_id)

    assert _git(tmp_path, "rev-parse", "HEAD") == head
    assert not (tmp_path / "evidence").exists()


def test_v28_scope_lineage_check_is_time_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "fieldtrue.memory_cycle.trusted_repository_git",
        lambda *_args: "/usr/bin/git",
    )

    def time_out(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        raise subprocess.TimeoutExpired(("git", "merge-base"), 30)

    monkeypatch.setattr("fieldtrue.memory_cycle.subprocess.run", time_out)

    with pytest.raises(MemoryCycleError, match="lineage could not be verified"):
        _git_is_ancestor(tmp_path, ancestor="a" * 40, descendant="b" * 40)


def test_v28_scope_preflight_rejects_coherent_evidence_substitution_without_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _seed_repo(tmp_path)
    _install_stubs(tmp_path, monkeypatch, exercise_v28_scope=True)
    correction = _seed_scope_correction_spec(tmp_path)
    audit = tmp_path / "docs/research/ITER001_SOURCE_ROLE_AUDIT.md"
    audit.write_bytes(audit.read_bytes() + b"substituted\n")
    _git(tmp_path, "add", audit.relative_to(tmp_path).as_posix())
    _git(tmp_path, "commit", "-qm", "coherently substitute correction evidence")
    monkeypatch.setattr("fieldtrue.memory_cycle._V28_SCOPE_CORRECTION", correction)
    head = _git(tmp_path, "rev-parse", "HEAD")

    with pytest.raises(MemoryCycleError, match="implementation bytes differ"):
        _cycle(
            tmp_path,
            v28_scope_correction_event_id="cycle-test-v28-scope-correction-v1",
        )

    assert _git(tmp_path, "rev-parse", "HEAD") == head
    assert _git(tmp_path, "status", "--porcelain") == ""
    assert not (tmp_path / "evidence").exists()


def test_cycle_forbids_a_second_v28_scope_correction_before_writing_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_repo(tmp_path)
    _install_stubs(tmp_path, monkeypatch, exercise_v28_scope=True)
    monkeypatch.setattr(
        "fieldtrue.memory_cycle._V28_SCOPE_CORRECTION",
        _seed_scope_correction_spec(tmp_path),
    )
    _cycle(
        tmp_path,
        v28_scope_correction_event_id="cycle-test-v28-scope-correction-v1",
    )
    head = _git(tmp_path, "rev-parse", "HEAD")

    with pytest.raises(MemoryCycleError, match="already retained"):
        _cycle(
            tmp_path,
            v28_scope_correction_event_id="cycle-test-v28-scope-correction-v2",
        )

    assert _git(tmp_path, "rev-parse", "HEAD") == head
    assert _git(tmp_path, "status", "--porcelain") == ""


def test_cycle_rejects_a_mismatched_v28_scope_correction_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_repo(tmp_path)
    _install_stubs(tmp_path, monkeypatch, exercise_v28_scope=True)
    monkeypatch.setattr(
        "fieldtrue.memory_cycle._V28_SCOPE_CORRECTION",
        _seed_scope_correction_spec(tmp_path, old="A different retained summary."),
    )

    with pytest.raises(MemoryCycleError, match="scope-correction target differs"):
        _cycle(
            tmp_path,
            v28_scope_correction_event_id="cycle-test-v28-scope-correction-v1",
        )


def test_cycle_refuses_a_dirty_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_repo(tmp_path)
    _install_stubs(tmp_path, monkeypatch)
    (tmp_path / "CONTINUITY.md").write_text("edited\n", encoding="utf-8")
    with pytest.raises(MemoryCycleError, match="dirty tree"):
        _cycle(tmp_path)


def test_cycle_refuses_a_failing_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A failing validation is a finding to fix, never a checkpoint to record.
    _seed_repo(tmp_path)
    _install_stubs(tmp_path, monkeypatch, receipt_result="fail")
    with pytest.raises(MemoryCycleError, match="did not pass"):
        _cycle(tmp_path)


def test_cycle_refuses_a_receipt_bound_to_the_wrong_head(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_repo(tmp_path)
    _install_stubs(tmp_path, monkeypatch, subject_override="b" * 40)
    with pytest.raises(MemoryCycleError, match="does not bind the implementation head"):
        _cycle(tmp_path)


def test_final_commit_cannot_smuggle_or_drop_a_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # If the render step produces no handoff change, the final commit would contain only the
    # ledger; the two-file rule must refuse rather than finalize a partial cycle.
    _seed_repo(tmp_path)
    _install_stubs(tmp_path, monkeypatch, render_writes_handoff=False)
    with pytest.raises(MemoryCycleError, match="exactly two files"):
        _cycle(tmp_path)


def test_cycle_surfaces_a_failing_committed_verifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_repo(tmp_path)

    def fake_receipt(repo_root: Path, *, receipt_id: str, producer_actor_id: str) -> Path:
        receipt = _receipt(_git(tmp_path, "rev-parse", "HEAD"))
        path = repo_root / f"evidence/validation/{receipt_id}/receipt.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(receipt.model_dump_json(), encoding="utf-8")
        return path

    def failing_inbar(repo_root: Path, *args: str) -> str:
        if args == ("memory", "verify"):
            raise MemoryCycleError("inbar memory verify failed: chain broken")
        if args == ("handoff", "render"):
            (repo_root / "HANDOFF.md").write_text("# rendered\n", encoding="utf-8")
        return ""

    monkeypatch.setattr("fieldtrue.memory_cycle.write_validation_receipt", fake_receipt)
    monkeypatch.setattr("fieldtrue.memory_cycle._run_inbar", failing_inbar)
    monkeypatch.setattr(
        "fieldtrue.memory_cycle._v28_scope_correction_is_required",
        lambda *_args, **_kwargs: False,
    )
    with pytest.raises(MemoryCycleError, match="chain broken"):
        _cycle(tmp_path)


def test_run_inbar_passes_through_success_and_surfaces_failure() -> None:
    from fieldtrue.memory_cycle import _run_inbar

    repo = Path(__file__).resolve().parents[2]
    output = _run_inbar(repo, "schemas", "check")
    assert "SCHEMAS_VERIFIED" in output
    with pytest.raises(MemoryCycleError, match="failed"):
        _run_inbar(repo, "not-a-command")
