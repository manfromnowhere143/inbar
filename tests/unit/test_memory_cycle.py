"""Controls for the receipt, ledger, and handoff cycle producer.

The cycle writes to an append-only hash-chained ledger and creates the exact two-commit
topology the handoff checker demands. A producer that could corrupt the chain, launder a
failing receipt, or smuggle a third file into the final commit would be worse than no
producer at all.
"""

from __future__ import annotations

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
from fieldtrue.memory_cycle import MemoryCycleError, produce_handoff_cycle

RECEIPT_ID = "inbar-core-validation-cycle-test"
NOW = datetime(2026, 7, 18, 12, 0, 0, tzinfo=UTC)


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
        "sequence": 152,
        "source_commit": "0" * 40,
        "stage": "mission-handoff",
        "status": "blocked",
        "summary": "Seed handoff state.",
    }
    verdict_body = dict(previous_body)
    verdict_body.update(
        {
            "event_id": "seed-source-verdict-v1",
            "event_type": "finding",
            "status": "negative",
            "sequence": 151,
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
        json.dumps(verdict_body, sort_keys=True, separators=(",", ":"))
        + "\n"
        + json.dumps(previous_body, sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="utf-8",
    )
    (root / "docs/research").mkdir(parents=True)
    (root / "docs/research/ITER001_SOURCE_ROLE_AUDIT.md").write_text("# audit\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "seed")


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
    return calls


def _cycle(root: Path) -> dict[str, str]:
    return produce_handoff_cycle(
        root,
        receipt_id=RECEIPT_ID,
        producer_actor_id="claude",
        summary="Recorded the census implementation checkpoint.",
        checkpoint_event_id="cycle-test-checkpoint-v1",
        handoff_event_id="cycle-test-handoff-v1",
        resource_event_id="cycle-test-resource-v1",
        source_verdict_event_id="cycle-test-source-verdict-v1",
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
    assert [event["sequence"] for event in events] == [151, 152, 153, 154, 155, 156]
    for previous, current in itertools.pairwise(events):
        assert current["previous_event_hash"] == previous["event_hash"]
        body = {k: v for k, v in current.items() if k != "event_hash"}
        assert sha256_value(body) == current["event_hash"]
    verdict, resource, checkpoint, handoff = events[2], events[3], events[4], events[5]
    assert verdict["event_type"] == "finding"
    assert verdict["source_commit"] == result["implementation_commit"]
    # The verdict did not change, so its frozen payload and summary carry forward verbatim.
    assert verdict["payload"] == events[0]["payload"]
    assert verdict["summary"] == events[0]["summary"]
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
    assert handoff["links"]["engine_boundary"] == "future-research-engine-shortcut-v2-lessons-v1"
    assert handoff["evidence"][0]["git_commit"] == result["implementation_commit"]
    assert checkpoint["links"]["resource_observation"] == "cycle-test-resource-v1"
    assert handoff["links"]["checkpoint"] == "cycle-test-checkpoint-v1"
    assert handoff["links"]["source_verdict"] == "cycle-test-source-verdict-v1"
    # The mission state did not change, so the handoff payload carries forward verbatim.
    assert handoff["payload"] == events[1]["payload"]


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
    with pytest.raises(MemoryCycleError, match="chain broken"):
        _cycle(tmp_path)


def test_run_inbar_passes_through_success_and_surfaces_failure() -> None:
    from fieldtrue.memory_cycle import _run_inbar

    repo = Path(__file__).resolve().parents[2]
    output = _run_inbar(repo, "schemas", "check")
    assert "SCHEMAS_VERIFIED" in output
    with pytest.raises(MemoryCycleError, match="failed"):
        _run_inbar(repo, "mission", "validate", "--expect-failure", "no-such-check")
