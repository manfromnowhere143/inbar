from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

import fieldtrue.handoff as handoff_module
from fieldtrue.canonical import canonical_json, canonical_json_pretty, sha256_bytes
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
from fieldtrue.handoff import HandoffError, check_handoff, render_handoff, write_handoff
from fieldtrue.memory import (
    AccessClass,
    EpistemicPhase,
    LabelAccess,
    MemoryEvidenceRef,
    MemoryStatus,
    ResearchMemoryRecord,
    load_memory_records,
)
from fieldtrue.mission import MissionValidation, ValidationCheck

_LEGACY_CHECKPOINT_EVENT_ID = "iter001-shortcut-v2-implementation-checkpoint-v1"
_LEGACY_HANDOFF_EVENT_ID = "iter001-shortcut-v2-activation-gates-v1"


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _legacy_recovery_memory(
    records: tuple[ResearchMemoryRecord, ...],
) -> tuple[ResearchMemoryRecord, ...]:
    legacy_handoff = next(
        record for record in records if record.event_id == _LEGACY_HANDOFF_EVENT_ID
    )
    engine_boundary = next(
        record
        for record in records
        if record.event_id == "future-research-engine-shortcut-v2-lessons-v1"
    )
    cutoff = max(legacy_handoff.sequence, engine_boundary.sequence)
    return tuple(record for record in records if record.sequence <= cutoff)


def _legacy_recovery_memory_bytes(records: tuple[ResearchMemoryRecord, ...]) -> bytes:
    return b"".join(canonical_json(record) + b"\n" for record in _legacy_recovery_memory(records))


@pytest.fixture(scope="module")
def memory_records() -> tuple[ResearchMemoryRecord, ...]:
    records = load_memory_records(_project_root() / "memory" / "research_engine_extraction.jsonl")
    # Legacy renderer tests require an immutable V1 seed. V2 tests append their own explicit tail.
    return _legacy_recovery_memory(records)


def _git(repo: Path, *arguments: str) -> str:
    return subprocess.run(  # noqa: S603 - tests use fixed Git arguments and repository paths
        [str(handoff_module.TRUSTED_GIT_PATH), *arguments],
        cwd=repo,
        check=True,
        capture_output=True,
        env=handoff_module.git_environment(),
        text=True,
    ).stdout.strip()


def _v28_scope_transition_fixture(tmp_path: Path) -> SimpleNamespace:
    repo = tmp_path / "v28-scope-transition"
    subprocess.run(  # noqa: S603 - fixed Git and local test repository source
        [
            str(handoff_module.TRUSTED_GIT_PATH),
            "clone",
            "--quiet",
            "--no-hardlinks",
            str(_project_root()),
            str(repo),
        ],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        env={**handoff_module.git_environment(), "GIT_ALLOW_PROTOCOL": "file"},
    )
    _git(repo, "config", "user.name", "Inbar V28 Correction Test")
    _git(repo, "config", "user.email", "v28-correction@example.invalid")
    for uri, _media_type, _role in handoff_module.V28_SCOPE_CORRECTION_EVIDENCE:
        destination = repo / uri
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((_project_root() / uri).read_bytes())
    _git(repo, "add", "-A")
    _git(repo, "commit", "--quiet", "--allow-empty", "-m", "correction evidence subject")
    implementation_commit = _git(repo, "rev-parse", "HEAD")

    existing = load_memory_records(_project_root() / handoff_module._MEMORY_PATH)
    by_id = {record.event_id: record for record in existing}
    target = by_id[handoff_module.V28_SCOPE_CORRECTION_TARGET_EVENT_ID]
    predecessor = by_id[handoff_module.V28_SCOPE_CORRECTION_PREDECESSOR_HANDOFF_ID]
    source_template = by_id["iter001-current-public-source-route-verdict-v29"]
    resource_template = by_id["inbar-core-validation-resource-observation-v29"]
    checkpoint_template = by_id["inbar-core-validation-checkpoint-v29"]
    correction_template = next(
        record for record in existing if record.event_type.value == "correction"
    )

    evidence = tuple(
        MemoryEvidenceRef(
            role=role,
            uri=uri,
            sha256=sha256_bytes((repo / uri).read_bytes()),
            git_commit=implementation_commit,
            media_type=media_type,
            access=AccessClass.INTERNAL,
            label_access=LabelAccess.NONE,
        )
        for uri, media_type, role in handoff_module.V28_SCOPE_CORRECTION_EVIDENCE
    )
    source = source_template.model_copy(
        update={
            "sequence": predecessor.sequence + 1,
            "event_id": handoff_module.V28_SCOPE_CORRECTION_SOURCE_EVENT_ID,
            "source_commit": implementation_commit,
        }
    )
    correction = correction_template.model_copy(
        update={
            "sequence": source.sequence + 1,
            "event_id": handoff_module.V28_SCOPE_CORRECTION_EVENT_ID,
            "stage": "evidence-correction",
            "status": MemoryStatus.RECORDED,
            "summary": handoff_module.V28_SCOPE_CORRECTION_SUMMARY,
            "payload": {
                "old": handoff_module.V28_SCOPE_CORRECTION_OLD,
                "corrected": handoff_module.V28_SCOPE_CORRECTION_CORRECTED,
                "authority_effect": "none",
            },
            "evidence": evidence,
            "links": {},
            "source_commit": implementation_commit,
            "corrects_event_id": target.event_id,
            "actor": predecessor.actor,
            "schema_version": "daniel.research-memory.v2",
            "mission_id": "inbar",
            "access": AccessClass.INTERNAL,
            "epistemic_phase": EpistemicPhase.RETROSPECTIVE,
            "cost_usd": "0",
            "manual_minutes": 0.0,
            "recurrence_key": None,
            "engine_requirement": None,
            "occurred_at": source.recorded_at,
            "recorded_at": source.recorded_at,
        }
    )
    resource = resource_template.model_copy(
        update={
            "sequence": correction.sequence + 1,
            "event_id": handoff_module.V28_SCOPE_CORRECTION_RESOURCE_EVENT_ID,
            "links": {"source_verdict": source.event_id},
        }
    )
    source_evidence = MemoryEvidenceRef(
        role="source",
        uri=evidence[0].uri,
        sha256=evidence[0].sha256,
        git_commit=implementation_commit,
        media_type=evidence[0].media_type,
        access=AccessClass.INTERNAL,
        label_access=LabelAccess.NONE,
    )
    validation_receipt = dict(checkpoint_template.payload["validation_receipt"])
    validation_receipt.update(
        {
            "path": (
                f"evidence/validation/{handoff_module.V28_SCOPE_CORRECTION_RECEIPT_ID}/receipt.json"
            ),
            "receipt_id": handoff_module.V28_SCOPE_CORRECTION_RECEIPT_ID,
        }
    )
    checkpoint = checkpoint_template.model_copy(
        update={
            "sequence": resource.sequence + 1,
            "event_id": handoff_module.V28_SCOPE_CORRECTION_CHECKPOINT_EVENT_ID,
            "source_commit": implementation_commit,
            "payload": {
                **checkpoint_template.payload,
                "implementation_commit": implementation_commit,
                "validation_receipt": validation_receipt,
            },
            "evidence": (source_evidence, checkpoint_template.evidence[1]),
            "links": {
                "resource_observation": resource.event_id,
                "source_verdict": source.event_id,
            },
        }
    )
    handoff_evidence = MemoryEvidenceRef(
        role="source",
        uri=evidence[1].uri,
        sha256=evidence[1].sha256,
        git_commit=implementation_commit,
        media_type=evidence[1].media_type,
        access=AccessClass.INTERNAL,
        label_access=LabelAccess.NONE,
    )
    successor = predecessor.model_copy(
        update={
            "sequence": checkpoint.sequence + 1,
            "event_id": handoff_module.V28_SCOPE_CORRECTION_HANDOFF_EVENT_ID,
            "source_commit": implementation_commit,
            "evidence": (handoff_evidence,),
            "links": {
                "checkpoint": checkpoint.event_id,
                "engine_boundary": handoff_module._ENGINE_BOUNDARY_EVENT_ID,
                "source_verdict": source.event_id,
            },
        }
    )
    records = (*existing, source, correction, resource, checkpoint, successor)
    return SimpleNamespace(
        repo=repo,
        records=records,
        implementation_commit=implementation_commit,
        target_id=target.event_id,
        source_id=source.event_id,
        correction_id=correction.event_id,
        resource_id=resource.event_id,
        checkpoint_id=checkpoint.event_id,
        successor_id=successor.event_id,
    )


def _git_object_bytes(repo: Path, commit: str, path: str) -> bytes:
    return subprocess.run(  # noqa: S603 - fixed Git with test-owned object and path values
        [str(handoff_module.TRUSTED_GIT_PATH), "show", f"{commit}:{path}"],
        cwd=repo,
        check=True,
        capture_output=True,
        env=handoff_module.git_environment(),
    ).stdout


def _rebind_transition_implementation(fixture: SimpleNamespace, commit: str) -> None:
    def rebound_evidence(evidence: MemoryEvidenceRef) -> MemoryEvidenceRef:
        return evidence.model_copy(
            update={
                "git_commit": commit,
                "sha256": sha256_bytes(_git_object_bytes(fixture.repo, commit, evidence.uri)),
            }
        )

    records: list[ResearchMemoryRecord] = []
    for record in fixture.records:
        if record.event_id == fixture.source_id:
            record = record.model_copy(update={"source_commit": commit})
        elif record.event_id == fixture.correction_id:
            record = record.model_copy(
                update={
                    "source_commit": commit,
                    "evidence": tuple(rebound_evidence(item) for item in record.evidence),
                }
            )
        elif record.event_id == fixture.checkpoint_id:
            record = record.model_copy(
                update={
                    "source_commit": commit,
                    "payload": {**record.payload, "implementation_commit": commit},
                    "evidence": (rebound_evidence(record.evidence[0]), *record.evidence[1:]),
                }
            )
        elif record.event_id == fixture.successor_id:
            record = record.model_copy(
                update={
                    "source_commit": commit,
                    "evidence": (rebound_evidence(record.evidence[0]),),
                }
            )
        records.append(record)
    fixture.records = tuple(records)


def _verify_v28_scope_transition(fixture: SimpleNamespace) -> None:
    by_id = {record.event_id: record for record in fixture.records}
    handoff_module._verify_v28_scope_correction_transition(
        fixture.repo,
        fixture.records,
        by_id,
        by_id[fixture.successor_id],
    )


def _replace_transition_record(
    fixture: SimpleNamespace,
    selected_event_id: str,
    **updates: object,
) -> None:
    fixture.records = tuple(
        record.model_copy(update=updates) if record.event_id == selected_event_id else record
        for record in fixture.records
    )


def test_v28_scope_correction_verifier_allows_the_exact_pretransition_state() -> None:
    records = load_memory_records(_project_root() / handoff_module._MEMORY_PATH)
    by_id = {record.event_id: record for record in records}
    predecessor = by_id[handoff_module.V28_SCOPE_CORRECTION_PREDECESSOR_HANDOFF_ID]

    assert predecessor.event_id == "inbar-core-validation-handoff-v29"
    assert predecessor.event_hash == handoff_module.V28_SCOPE_CORRECTION_PREDECESSOR_HANDOFF_HASH
    assert (
        predecessor.source_commit
        == handoff_module.V28_SCOPE_CORRECTION_PREDECESSOR_HANDOFF_SOURCE_COMMIT
    )
    assert predecessor.sequence == handoff_module.V28_SCOPE_CORRECTION_PREDECESSOR_HANDOFF_SEQUENCE
    assert handoff_module.V28_SCOPE_CORRECTION_EVENT_ID not in by_id

    handoff_module._verify_v28_scope_correction_transition(
        _project_root(),
        records,
        by_id,
        predecessor,
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("event_hash", "0" * 64),
        ("source_commit", "0" * 40),
        ("sequence", 260),
    ],
)
def test_v28_scope_correction_verifier_rejects_historical_v29_predecessor_drift(
    field: str,
    value: object,
) -> None:
    records = load_memory_records(_project_root() / handoff_module._MEMORY_PATH)
    predecessor_id = handoff_module.V28_SCOPE_CORRECTION_PREDECESSOR_HANDOFF_ID
    mutated = tuple(
        record.model_copy(update={field: value}) if record.event_id == predecessor_id else record
        for record in records
    )
    by_id = {record.event_id: record for record in mutated}

    with pytest.raises(HandoffError, match="predecessor handoff differs"):
        handoff_module._verify_v28_scope_correction_transition(
            _project_root(),
            mutated,
            by_id,
            by_id[predecessor_id],
        )


def test_v28_scope_correction_verifier_rejects_a_prospective_id_collision() -> None:
    records = load_memory_records(_project_root() / handoff_module._MEMORY_PATH)
    predecessor = records[-1]
    collision = predecessor.model_copy(
        update={
            "corrects_event_id": None,
            "event_id": handoff_module.V28_SCOPE_CORRECTION_EVENT_ID,
            "sequence": predecessor.sequence + 1,
        }
    )
    collided = (*records, collision)
    by_id = {record.event_id: record for record in collided}

    with pytest.raises(HandoffError, match="event ID collides"):
        handoff_module._verify_v28_scope_correction_transition(
            _project_root(),
            collided,
            by_id,
            predecessor,
        )


def test_v28_scope_correction_verifier_accepts_the_exact_transition(tmp_path: Path) -> None:
    fixture = _v28_scope_transition_fixture(tmp_path)

    _verify_v28_scope_transition(fixture)


@pytest.mark.parametrize(
    ("fixture_id_field", "wrong_id"),
    [
        ("source_id", "fixture-wrong-v30-source"),
        ("resource_id", "fixture-wrong-v30-resource"),
        ("checkpoint_id", "fixture-wrong-v30-checkpoint"),
        ("successor_id", "fixture-wrong-v30-handoff"),
    ],
)
def test_v28_scope_correction_verifier_rejects_wrong_v30_topology_ids(
    tmp_path: Path,
    fixture_id_field: str,
    wrong_id: str,
) -> None:
    fixture = _v28_scope_transition_fixture(tmp_path)
    selected_id = getattr(fixture, fixture_id_field)
    _replace_transition_record(fixture, selected_id, event_id=wrong_id)
    setattr(fixture, fixture_id_field, wrong_id)

    with pytest.raises(HandoffError):
        _verify_v28_scope_transition(fixture)


def test_v28_scope_correction_verifier_rejects_a_coherent_wrong_v30_receipt_id(
    tmp_path: Path,
) -> None:
    fixture = _v28_scope_transition_fixture(tmp_path)
    checkpoint = next(
        record for record in fixture.records if record.event_id == fixture.checkpoint_id
    )
    validation_receipt = dict(checkpoint.payload["validation_receipt"])
    validation_receipt.update(
        {
            "path": "evidence/validation/fixture-wrong-v30/receipt.json",
            "receipt_id": "fixture-wrong-v30",
        }
    )
    _replace_transition_record(
        fixture,
        fixture.checkpoint_id,
        payload={**checkpoint.payload, "validation_receipt": validation_receipt},
    )

    with pytest.raises(HandoffError, match="retained v28 scope correction differs"):
        _verify_v28_scope_transition(fixture)


def test_v28_scope_correction_verifier_rejects_a_skipped_first_successor(
    tmp_path: Path,
) -> None:
    fixture = _v28_scope_transition_fixture(tmp_path)
    fixture.records = tuple(
        record for record in fixture.records if record.event_id != fixture.correction_id
    )

    with pytest.raises(HandoffError, match="first post-v29 handoff requires exactly one"):
        _verify_v28_scope_transition(fixture)


def test_v28_scope_correction_verifier_rejects_the_predecessor_as_implementation(
    tmp_path: Path,
) -> None:
    fixture = _v28_scope_transition_fixture(tmp_path)
    _rebind_transition_implementation(
        fixture,
        handoff_module.V28_SCOPE_CORRECTION_PREDECESSOR_FINAL_COMMIT,
    )

    with pytest.raises(HandoffError, match="outside the frozen predecessor lineage"):
        _verify_v28_scope_transition(fixture)


def test_v28_scope_correction_verifier_rejects_disconnected_coherent_evidence(
    tmp_path: Path,
) -> None:
    fixture = _v28_scope_transition_fixture(tmp_path)
    tree = _git(fixture.repo, "rev-parse", f"{fixture.implementation_commit}^{{tree}}")
    disconnected = _git(fixture.repo, "commit-tree", tree, "-m", "disconnected evidence")
    _rebind_transition_implementation(fixture, disconnected)

    with pytest.raises(HandoffError, match="outside the frozen predecessor lineage"):
        _verify_v28_scope_transition(fixture)


def test_v28_scope_correction_verifier_rejects_coherent_evidence_substitution(
    tmp_path: Path,
) -> None:
    fixture = _v28_scope_transition_fixture(tmp_path)
    substituted_path = fixture.repo / handoff_module.V28_SCOPE_CORRECTION_EVIDENCE[0][0]
    substituted_path.write_bytes(substituted_path.read_bytes() + b"\n# coherent substitution\n")
    _git(fixture.repo, "add", substituted_path.relative_to(fixture.repo).as_posix())
    _git(fixture.repo, "commit", "--quiet", "-m", "substitute coherent evidence")
    substituted = _git(fixture.repo, "rev-parse", "HEAD")
    _rebind_transition_implementation(fixture, substituted)

    with pytest.raises(HandoffError, match="scope-correction evidence differs"):
        _verify_v28_scope_transition(fixture)


def test_v28_scope_correction_verifier_rejects_a_versioned_tail_without_the_target(
    tmp_path: Path,
) -> None:
    fixture = _v28_scope_transition_fixture(tmp_path)
    fixture.records = tuple(
        record for record in fixture.records if record.event_id != fixture.target_id
    )

    with pytest.raises(
        HandoffError,
        match="versioned handoff is missing the frozen v28 transition target",
    ):
        _verify_v28_scope_transition(fixture)


@pytest.mark.parametrize(
    "mutation",
    [
        "omitted",
        "duplicate",
        "wrong_target",
        "event_id",
        "target_hash",
        "target_source",
        "target_sequence",
        "payload",
        "source_commit",
        "summary",
        "evidence_path",
        "evidence_hash",
        "evidence_set",
        "order",
        "intervening_event",
        "schema_identity",
        "access",
        "epistemic_phase",
        "cost_usd",
        "manual_minutes",
        "recurrence_key",
        "engine_requirement",
        "timestamp",
        "actor_kind",
        "actor_drift",
    ],
)
def test_v28_scope_correction_verifier_rejects_every_transition_drift(
    tmp_path: Path,
    mutation: str,
) -> None:
    fixture = _v28_scope_transition_fixture(tmp_path)
    correction = next(
        record for record in fixture.records if record.event_id == fixture.correction_id
    )
    if mutation == "omitted":
        fixture.records = tuple(
            record for record in fixture.records if record.event_id != fixture.correction_id
        )
    elif mutation == "duplicate":
        fixture.records = (
            *fixture.records,
            correction.model_copy(
                update={
                    "event_id": "fixture-duplicate-v28-scope-correction",
                    "sequence": fixture.records[-1].sequence + 1,
                }
            ),
        )
    elif mutation == "wrong_target":
        _replace_transition_record(
            fixture,
            fixture.correction_id,
            corrects_event_id="inbar-core-validation-checkpoint-v27",
        )
    elif mutation == "event_id":
        _replace_transition_record(
            fixture,
            fixture.correction_id,
            event_id="fixture-wrong-v28-scope-correction-id",
        )
    elif mutation == "target_hash":
        _replace_transition_record(fixture, fixture.target_id, event_hash="0" * 64)
    elif mutation == "target_source":
        _replace_transition_record(fixture, fixture.target_id, source_commit="0" * 40)
    elif mutation == "target_sequence":
        target = next(record for record in fixture.records if record.event_id == fixture.target_id)
        _replace_transition_record(
            fixture,
            fixture.target_id,
            sequence=target.sequence - 1,
        )
    elif mutation == "payload":
        _replace_transition_record(
            fixture,
            fixture.correction_id,
            payload={**correction.payload, "corrected": "A fabricated correction."},
        )
    elif mutation == "source_commit":
        _replace_transition_record(fixture, fixture.correction_id, source_commit="0" * 40)
    elif mutation == "summary":
        _replace_transition_record(
            fixture,
            fixture.correction_id,
            summary="A different retained correction.",
        )
    elif mutation == "evidence_set":
        _replace_transition_record(
            fixture,
            fixture.correction_id,
            evidence=correction.evidence[:-1],
        )
    elif mutation == "order":
        _replace_transition_record(
            fixture,
            fixture.correction_id,
            sequence=correction.sequence - 1,
        )
    elif mutation == "intervening_event":
        source = next(record for record in fixture.records if record.event_id == fixture.source_id)
        intervening = source.model_copy(
            update={
                "event_id": "fixture-intervening-event",
                "sequence": source.sequence + 1,
            }
        )
        shifted = {
            fixture.correction_id,
            fixture.resource_id,
            fixture.checkpoint_id,
            fixture.successor_id,
        }
        records: list[ResearchMemoryRecord] = []
        for record in fixture.records:
            records.append(
                record.model_copy(update={"sequence": record.sequence + 1})
                if record.event_id in shifted
                else record
            )
            if record.event_id == fixture.source_id:
                records.append(intervening)
        fixture.records = tuple(records)
    elif mutation == "schema_identity":
        _replace_transition_record(
            fixture,
            fixture.correction_id,
            schema_version="daniel.research-memory.v1",
            mission_id="fieldtrue",
        )
    elif mutation == "access":
        _replace_transition_record(
            fixture,
            fixture.correction_id,
            access=AccessClass.PUBLIC,
        )
    elif mutation == "epistemic_phase":
        _replace_transition_record(
            fixture,
            fixture.correction_id,
            epistemic_phase=EpistemicPhase.PROSPECTIVE,
        )
    elif mutation == "cost_usd":
        _replace_transition_record(fixture, fixture.correction_id, cost_usd="9.5")
    elif mutation == "manual_minutes":
        _replace_transition_record(fixture, fixture.correction_id, manual_minutes=12.0)
    elif mutation == "recurrence_key":
        _replace_transition_record(
            fixture,
            fixture.correction_id,
            recurrence_key="fixture-recurrence",
        )
    elif mutation == "engine_requirement":
        _replace_transition_record(
            fixture,
            fixture.correction_id,
            engine_requirement="A fabricated engine requirement.",
        )
    elif mutation == "timestamp":
        _replace_transition_record(
            fixture,
            fixture.correction_id,
            recorded_at=correction.recorded_at + timedelta(seconds=1),
        )
    elif mutation == "actor_kind":
        actor = correction.actor.model_copy(update={"kind": "human"})
        fixture.records = tuple(
            record.model_copy(update={"actor": actor})
            if record.event_id
            in {
                fixture.source_id,
                fixture.correction_id,
                fixture.resource_id,
                fixture.checkpoint_id,
                fixture.successor_id,
            }
            else record
            for record in fixture.records
        )
    elif mutation == "actor_drift":
        source = next(record for record in fixture.records if record.event_id == fixture.source_id)
        _replace_transition_record(
            fixture,
            fixture.source_id,
            actor=source.actor.model_copy(update={"actor_id": "fixture-other-agent"}),
        )
    else:
        evidence_update = (
            {"uri": "src/fieldtrue/control_protocol.py"}
            if mutation == "evidence_path"
            else {"sha256": "0" * 64}
        )
        evidence = correction.evidence[0].model_copy(update=evidence_update)
        _replace_transition_record(
            fixture,
            fixture.correction_id,
            evidence=(evidence, *correction.evidence[1:]),
        )

    with pytest.raises(HandoffError, match=r"v28|v30|post-v29"):
        _verify_v28_scope_transition(fixture)


@pytest.fixture(scope="module")
def committed_worker_repo(tmp_path_factory: pytest.TempPathFactory) -> Path:
    ambient_source = _project_root()
    fixture_root = tmp_path_factory.mktemp("handoff-worker")
    source = fixture_root / "source"
    destination = fixture_root / "repository"
    clone_environment = handoff_module.git_environment()
    clone_environment["GIT_ALLOW_PROTOCOL"] = "file"
    subprocess.run(  # noqa: S603 - fixed trusted Git and local test paths
        [
            str(handoff_module.TRUSTED_GIT_PATH),
            "clone",
            "--quiet",
            "--no-hardlinks",
            "--",
            str(ambient_source),
            str(source),
        ],
        cwd=fixture_root,
        check=True,
        capture_output=True,
        env=clone_environment,
        timeout=60,
    )
    _git(source, "config", "user.name", "Inbar Handoff Test")
    _git(source, "config", "user.email", "handoff@example.invalid")

    ambient_manifest = handoff_module._recovery_manifest(ambient_source)
    ambient_memory, ambient_memory_metadata = handoff_module._read_regular_file_snapshot(
        ambient_source,
        handoff_module._MEMORY_PATH,
        handoff_module._MEMORY_PATH,
    )
    legacy_memory = _legacy_recovery_memory_bytes(
        load_memory_records(_project_root() / handoff_module._MEMORY_PATH)
    )
    assert ambient_memory.startswith(legacy_memory)
    handoff_module._clear_snapshot_worktree(source)
    for item in ambient_manifest.files:
        data, metadata = handoff_module._read_regular_file_snapshot(
            ambient_source,
            item.path,
            f"worker fixture source {item.path}",
        )
        assert metadata == item.metadata
        assert len(data) == item.size
        assert sha256_bytes(data) == item.sha256
        handoff_module._write_snapshot_file(source, item.path, data, metadata)
    handoff_module._write_snapshot_file(
        source,
        handoff_module._MEMORY_PATH,
        legacy_memory,
        ambient_memory_metadata,
    )
    _git(source, "add", "-f", "-A")
    _git(source, "commit", "--quiet", "--allow-empty", "-m", "freeze worker source")

    git = handoff_module.trusted_repository_git(source, handoff_module.TRUSTED_GIT_PATH)
    head = handoff_module._git_head(source, git)
    recovery_manifest = handoff_module._recovery_manifest(source)
    memory_bytes, memory_metadata = handoff_module._read_regular_file_snapshot(
        source,
        handoff_module._MEMORY_PATH,
        handoff_module._MEMORY_PATH,
    )
    handoff_module._materialize_repository_snapshot(
        source,
        destination,
        git=git,
        head=head,
        recovery_manifest=recovery_manifest,
        memory_bytes=memory_bytes,
        memory_metadata=memory_metadata,
    )
    _git(destination, "config", "user.name", "Inbar Handoff Test")
    _git(destination, "config", "user.email", "handoff@example.invalid")
    _git(destination, "add", "-A")
    _git(destination, "commit", "--quiet", "--allow-empty", "-m", "freeze worker fixture")
    return destination


def _build_handoff_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "mission-clone"
    inputs: dict[str, dict[str, object]] = {
        "mission/contract.json": {
            "mission_id": "inbar",
            "name": "Inbar",
            "owner": "Daniel Wahnich",
            "legacy_protocol_namespace": "fieldtrue",
            "research_engine_policy": (
                "deferred_to_separate_repository_after_multiple_complete_cycles"
            ),
            "source_digest_fixture": "one",
        },
        "mission/loop.json": {
            "current_stage": "corpus_qualification",
            "publication_transition": {"status": "blocked"},
        },
        "mission/name.json": {
            "canonical_slug": "inbar",
            "status": "internally_adopted_pending_professional_clearance",
        },
        "protocol/acquisition/iter001_contract.json": {
            "iteration_id": "iter001_physical_causal_evidence_acquisition",
            "control_authority_status": "bootstrap",
        },
    }
    for relative, value in inputs.items():
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    memory_path = repo / "memory" / "research_engine_extraction.jsonl"
    memory_path.parent.mkdir(parents=True)
    memory_path.write_text("fixture memory bytes\n", encoding="utf-8")
    for binding in handoff_module._BOUND_FIELDTRUE_MODULES:
        source_path = repo / binding.repository_path
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_bytes(binding.imported_bytes)
    for module_name in sorted(handoff_module._HANDOFF_ALLOWED_PRELOADED_MODULE_NAMES):
        relative = Path("src", *module_name.split(".")).with_suffix(".py")
        source_path = repo / relative
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_bytes((_project_root() / relative).read_bytes())
    source_root = repo / "src" / "fieldtrue"
    (source_root / "second.py").write_text("VALUE = 2\n", encoding="utf-8")
    schema_root = repo / "protocol" / "schemas"
    schema_root.mkdir(parents=True)
    (schema_root / "alpha.schema.json").write_bytes(b'{"title":"alpha"}\n')
    (schema_root / "beta.schema.json").write_bytes(b'{"title":"beta"}\n')
    recovery_inputs = {
        ".github/workflows/ci.yml": b"name: fixture-ci\n",
        "README.md": b"# Fixture mission\n",
        "claims/registry.jsonl": b'{"claim":"blocked"}\n',
        "docs/ARCHITECTURE.md": b"# Architecture\n",
        "docs/research/ITER001_SOURCE_ROLE_AUDIT.md": (
            b"# Iteration 001 Source Role Audit\n\nBounded fixture audit.\n"
        ),
        "protocol/gate_controls/credibility_v1.json": (
            _project_root() / "protocol/gate_controls/credibility_v1.json"
        ).read_bytes(),
        "proofs/authority.txt": b"no authority\n",
        "scripts/verify.py": b"VALUE = 'verify'\n",
        "tests/test_fixture.py": b"def test_fixture(): pass\n",
    }
    for relative, content in recovery_inputs.items():
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return repo


@pytest.fixture
def handoff_repo(tmp_path: Path) -> Path:
    return _build_handoff_repo(tmp_path)


def _mission_report(
    *,
    extra_failures: tuple[str, ...] = (),
    omit_expected: bool = False,
) -> MissionValidation:
    check_ids = list(handoff_module._EXPECTED_MISSION_CHECK_IDS)
    if omit_expected:
        check_ids[check_ids.index("iter001-acquisition-contract")] = "fixture-replacement-check"
    for index, check_id in enumerate(extra_failures, start=1):
        check_ids[-index] = check_id
    checks = []
    for check_id in check_ids:
        if check_id == "iter001-acquisition-contract":
            checks.append(
                ValidationCheck(
                    check_id=check_id,
                    passed=False,
                    detail=(
                        "Iteration 001 acquisition contract failed: canonical control authority "
                        "is not sealed"
                    ),
                )
            )
        elif check_id in extra_failures:
            checks.append(ValidationCheck(check_id=check_id, passed=False, detail="unexpected"))
        else:
            checks.append(ValidationCheck(check_id=check_id, passed=True, detail="verified"))
    assert len(checks) == 22
    return MissionValidation(passed=all(check.passed for check in checks), checks=tuple(checks))


def _install_verified_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    memory_records: tuple[ResearchMemoryRecord, ...],
    *,
    report: MissionValidation | None = None,
    schema_errors: list[str] | None = None,
) -> None:
    monkeypatch.setattr(
        handoff_module,
        "_render_snapshot_bound",
        handoff_module._render_in_process,
    )
    monkeypatch.setattr(handoff_module, "load_memory_records_bytes", lambda _data: memory_records)
    monkeypatch.setattr(
        handoff_module,
        "validate_mission",
        lambda _repo: report or _mission_report(),
    )
    monkeypatch.setattr(
        handoff_module,
        "schema_documents",
        lambda: {
            "alpha.schema.json": b'{"title":"alpha"}\n',
            "beta.schema.json": b'{"title":"beta"}\n',
        },
    )
    monkeypatch.setattr(
        handoff_module,
        "_verify_v28_scope_correction_transition",
        lambda *_args: None,
    )
    if schema_errors is not None:
        monkeypatch.setattr(
            handoff_module,
            "schema_documents",
            lambda: {
                "alpha.schema.json": b'{"title":"changed"}\n',
                "beta.schema.json": b'{"title":"beta"}\n',
            },
        )


def _input_digest(document: bytes) -> str:
    match = re.search(rb"Generated-input digest: `([0-9a-f]{64})`", document)
    assert match is not None
    return match.group(1).decode("ascii")


def _replace_record(
    records: tuple[ResearchMemoryRecord, ...],
    event_id: str,
    **updates: object,
) -> tuple[ResearchMemoryRecord, ...]:
    return tuple(
        record.model_copy(update=updates) if record.event_id == event_id else record
        for record in records
    )


def _selected_recovery_records(
    records: tuple[ResearchMemoryRecord, ...],
) -> tuple[ResearchMemoryRecord, ResearchMemoryRecord]:
    handoff = max(
        (
            record
            for record in records
            if record.mission_id == "inbar"
            and record.event_type == handoff_module.MemoryEventType.HANDOFF
        ),
        key=lambda record: record.sequence,
    )
    checkpoint_id = handoff.links["checkpoint"]
    checkpoint = next(record for record in records if record.event_id == checkpoint_id)
    return checkpoint, handoff


def _versioned_recovery_records(
    records: tuple[ResearchMemoryRecord, ...],
) -> tuple[ResearchMemoryRecord, ResearchMemoryRecord]:
    prior_checkpoint, prior_handoff = _selected_recovery_records(records)
    validation = {
        **prior_checkpoint.payload["validation"],
        "mission_check_ids": list(handoff_module._EXPECTED_MISSION_CHECK_IDS),
    }
    checkpoint = prior_checkpoint.model_copy(
        update={
            "sequence": records[-1].sequence + 1,
            "event_id": "fixture-versioned-checkpoint",
            "stage": "mission-handoff",
            "payload": {
                **prior_checkpoint.payload,
                "action": handoff_module.RECOVERY_CHECKPOINT_ACTION,
                "authority_effect": handoff_module.RECOVERY_CHECKPOINT_AUTHORITY_EFFECT,
                "handoff_contract": "inbar.handoff-checkpoint.v1",
                "outcome": handoff_module.RECOVERY_CHECKPOINT_OUTCOME,
                "validation": validation,
            },
        }
    )
    handoff = prior_handoff.model_copy(
        update={
            "sequence": checkpoint.sequence + 1,
            "event_id": "fixture-versioned-handoff",
            "stage": "mission-handoff",
            "links": {
                "checkpoint": checkpoint.event_id,
                "engine_boundary": "future-research-engine-shortcut-v2-lessons-v1",
                "source_verdict": "iter001-public-substrate-verdict-v1",
            },
            "payload": {
                **prior_handoff.payload,
                "forbidden_until_activation": list(handoff_module._CANONICAL_FORBIDDEN_ACTIONS),
                "handoff_contract": "inbar.handoff-state.v1",
                "next_action": handoff_module.RECOVERY_HANDOFF_NEXT_ACTION,
                "state": handoff_module.RECOVERY_HANDOFF_STATE,
            },
        }
    )
    return checkpoint, handoff


def _write_validation_artifact(
    repo: Path,
    relative: str,
    data: bytes,
    media_type: str,
) -> EngineeringValidationArtifact:
    path = repo / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return EngineeringValidationArtifact(
        path=relative,
        sha256=sha256_bytes(data),
        bytes=len(data),
        media_type=media_type,
    )


def _validation_coverage_bytes(
    paths: tuple[str, ...] = ("src/fieldtrue/fixture.py",),
) -> bytes:
    file_summary = {
        "covered_lines": 10,
        "num_statements": 10,
        "percent_covered": 95.0,
        "percent_covered_display": "95",
        "missing_lines": 0,
        "excluded_lines": 0,
        "num_branches": 10,
        "num_partial_branches": 0,
        "covered_branches": 9,
        "missing_branches": 1,
    }
    count = len(paths)
    totals = {
        **file_summary,
        "covered_lines": 10 * count,
        "num_statements": 10 * count,
        "missing_lines": 0,
        "covered_branches": 9 * count,
        "num_branches": 10 * count,
        "missing_branches": count,
    }
    return canonical_json_pretty(
        {
            "meta": {
                "branch_coverage": True,
                "format": 3,
                "show_contexts": False,
                "timestamp": "2026-07-16T10:00:00",
                "version": "7.15.1",
            },
            "files": {
                path: {
                    "executed_lines": list(range(1, 11)),
                    "missing_lines": [],
                    "excluded_lines": [],
                    "executed_branches": [[line, line + 1] for line in range(1, 10)],
                    "missing_branches": [[10, 11]],
                    "summary": file_summary,
                }
                for path in paths
            },
            "totals": totals,
        }
    )


def _fixture_credibility_nodes() -> tuple[str, ...]:
    registry = json.loads(
        (_project_root() / "protocol/gate_controls/credibility_v1.json").read_text(encoding="utf-8")
    )
    return tuple(
        sorted(
            {
                control[role]
                for control in registry["controls"]
                for role in handoff_module._CREDIBILITY_GATE_CONTROL_ROLES
            }
        )
    )


def _validation_junit_bytes() -> bytes:
    cases = []
    for node_id in _fixture_credibility_nodes():
        relative, function_name = node_id.split("::")
        classname = ".".join(Path(relative).with_suffix("").parts)
        cases.append(f'<testcase classname="{classname}" name="{function_name}" time="0.1" />')
    tests = len(cases)
    duration = f"{tests / 10:.1f}"
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        f'<testsuites tests="{tests}" failures="0" errors="0" skipped="0" time="{duration}">'
        f'<testsuite name="pytest" tests="{tests}" failures="0" errors="0" skipped="0" '
        f'time="{duration}">' + "".join(cases) + "</testsuite></testsuites>"
    ).encode("utf-8")


def _v2_validation_context(
    repo: Path,
    records: tuple[ResearchMemoryRecord, ...],
    *,
    actor_id: str | None = None,
    coverage_observation: tuple[int, int, int, int] | None = None,
    coverage_paths_override: tuple[str, ...] | None = None,
    credential_artifact: bool = False,
    empty_step_logs: bool = False,
    executable_artifact: bool = False,
    executable_source: bool = False,
    extra_evidence_path: str | None = None,
    insert_parent_commit: bool = False,
    mission_check_ids: tuple[str, ...] | None = None,
    noncanonical_receipt: bool = False,
    overlap_steps: bool = False,
    plan_override: tuple[str, tuple[str, ...]] | None = None,
    preexisting_validation_file: bool = False,
    prior_integration_base: bool = False,
    pytest_counts: tuple[int, int, int, int] = (11, 0, 0, 0),
) -> SimpleNamespace:
    _git(repo, "init", "--quiet", "--initial-branch=main")
    _git(repo, "config", "user.name", "Inbar Validation Test")
    _git(repo, "config", "user.email", "validation@example.invalid")
    if prior_integration_base:
        _git(repo, "add", "-A")
        _git(repo, "commit", "--quiet", "-m", "prior integration base")
        (repo / "implementation-subject.txt").write_text(
            "implementation change\n",
            encoding="utf-8",
        )
    if preexisting_validation_file:
        preexisting = (
            repo / "evidence/validation/validation.fixture.v2/preexisting-unlisted-artifact.txt"
        )
        preexisting.parent.mkdir(parents=True, exist_ok=True)
        preexisting.write_text("pre-existing and unlisted\n", encoding="utf-8")
    if executable_source:
        (repo / "src/fieldtrue/second.py").chmod(0o755)
    _git(repo, "add", "-A")
    _git(repo, "commit", "--quiet", "-m", "implementation subject")
    subject_commit = _git(repo, "rev-parse", "HEAD")
    subject_tree = _git(repo, "rev-parse", "HEAD^{tree}")
    subject_python_paths = tuple(
        path
        for path in _git(
            repo,
            "ls-tree",
            "-r",
            "--name-only",
            subject_commit,
            "--",
            "src/fieldtrue",
        ).splitlines()
        if path.endswith(".py")
    )
    coverage_paths = coverage_paths_override or subject_python_paths
    if insert_parent_commit:
        intermediate = repo / "intermediate-parent.txt"
        intermediate.write_text("unexpected parent\n", encoding="utf-8")
        _git(repo, "add", intermediate.name)
        _git(repo, "commit", "--quiet", "-m", "intermediate parent")

    receipt_id = "validation.fixture.v2"
    evidence_root = f"evidence/validation/{receipt_id}"
    expected_plan = list(handoff_module._expected_validation_plan(receipt_id))
    if plan_override is not None:
        target_step, target_argv = plan_override
        expected_plan = [
            (step_id, target_argv if step_id == target_step else argv)
            for step_id, argv in expected_plan
        ]
    base_time = datetime(2026, 7, 16, 10, 0, tzinfo=UTC)
    steps: list[EngineeringValidationStep] = []
    for index, (step_id, argv) in enumerate(expected_plan):
        stdout_data = b"" if empty_step_logs else f"{step_id}: pass\n".encode()
        if credential_artifact and step_id == "ruff-check":
            stdout_data = ("AK" + "IA" + "A" * 16).encode("ascii")
        stdout = _write_validation_artifact(
            repo,
            f"{evidence_root}/{step_id}.stdout.txt",
            stdout_data,
            handoff_module._VALIDATION_LOG_MEDIA_TYPE,
        )
        stderr = _write_validation_artifact(
            repo,
            f"{evidence_root}/{step_id}.stderr.txt",
            b"",
            handoff_module._VALIDATION_LOG_MEDIA_TYPE,
        )
        started_at = base_time + timedelta(seconds=index * 2)
        if overlap_steps and index == 1:
            started_at = base_time + timedelta(milliseconds=500)
        steps.append(
            EngineeringValidationStep(
                step_id=step_id,
                argv=argv,
                working_directory=".",
                started_at=started_at,
                finished_at=started_at + timedelta(seconds=1),
                duration_ms=1_000,
                expected_exit_code=0,
                observed_exit_code=0,
                result="pass",
                stdout=stdout,
                stderr=stderr,
            )
        )
    junit = _write_validation_artifact(
        repo,
        f"{evidence_root}/pytest.junit.xml",
        _validation_junit_bytes(),
        handoff_module._VALIDATION_JUNIT_MEDIA_TYPE,
    )
    coverage = _write_validation_artifact(
        repo,
        f"{evidence_root}/coverage.json",
        _validation_coverage_bytes(coverage_paths),
        handoff_module._VALIDATION_COVERAGE_MEDIA_TYPE,
    )
    checkpoint_template, handoff_template = _selected_recovery_records(records)
    producer_actor_id = actor_id or checkpoint_template.actor.actor_id
    mission_ids = mission_check_ids or handoff_module._EXPECTED_MISSION_CHECK_IDS
    tests_passed, tests_failed, tests_errors, tests_skipped = pytest_counts
    observed_coverage = coverage_observation or (
        10 * len(coverage_paths),
        10 * len(coverage_paths),
        9 * len(coverage_paths),
        10 * len(coverage_paths),
    )
    covered_lines, num_statements, covered_branches, num_branches = observed_coverage
    receipt = EngineeringValidationReceipt(
        schema_version="inbar.engineering-validation-receipt.v1",
        receipt_id=receipt_id,
        mission_id="inbar",
        subject_commit=subject_commit,
        subject_tree=subject_tree,
        plan_id="inbar.core-engineering-validation.v1",
        plan_sha256=engineering_validation_plan_sha256(tuple(steps)),
        started_at=base_time - timedelta(seconds=1),
        finished_at=base_time + timedelta(seconds=16),
        producer_actor_id=producer_actor_id,
        assurance_scope="same-operator-engineering-observation-no-independent-attestation",
        independent_attestation=False,
        environment=EngineeringValidationEnvironment(
            platform="test-platform",
            machine="test-machine",
            python_version="3.12.13",
            uv_version="0.11.28",
        ),
        steps=tuple(steps),
        pytest_observation=EngineeringValidationPytestObservation(
            step_id="pytest-cov",
            junit_xml=junit,
            coverage_json=coverage,
            tests_passed=tests_passed,
            tests_failed=tests_failed,
            tests_errors=tests_errors,
            tests_skipped=tests_skipped,
            covered_lines=covered_lines,
            num_statements=num_statements,
            covered_branches=covered_branches,
            num_branches=num_branches,
        ),
        mission_observation=EngineeringValidationMissionObservation(
            step_id="mission-validate",
            mission_check_ids=mission_ids,
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
        result="pass",
    )
    receipt_path = repo / evidence_root / "receipt.json"
    if noncanonical_receipt:
        receipt_path.write_text(
            json.dumps(receipt.model_dump(mode="json"), sort_keys=False), encoding="utf-8"
        )
    else:
        receipt_path.write_bytes(canonical_json_pretty(receipt))
    if executable_artifact:
        (repo / evidence_root / "ruff-check.stdout.txt").chmod(0o755)
    if extra_evidence_path is not None:
        extra = repo / extra_evidence_path
        extra.parent.mkdir(parents=True, exist_ok=True)
        extra.write_text("not listed by the receipt\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "--quiet", "-m", "validation evidence")
    evidence_commit = _git(repo, "rev-parse", "HEAD")

    source_path = handoff_module._CURRENT_SOURCE_AUDIT_PATH
    source_sha = sha256_bytes((repo / source_path).read_bytes())
    source_ref = MemoryEvidenceRef(
        role="source",
        uri=source_path,
        sha256=source_sha,
        git_commit=subject_commit,
        media_type="text/markdown",
        access=AccessClass.INTERNAL,
        label_access=LabelAccess.NONE,
    )
    receipt_bytes = receipt_path.read_bytes()
    verifier_ref = MemoryEvidenceRef(
        role="verifier",
        uri=receipt_path.relative_to(repo).as_posix(),
        sha256=sha256_bytes(receipt_bytes),
        git_commit=evidence_commit,
        media_type=handoff_module._VALIDATION_RECEIPT_MEDIA_TYPE,
        access=AccessClass.INTERNAL,
        label_access=LabelAccess.NONE,
    )
    sequence = records[-1].sequence
    legacy_source = next(
        record for record in records if record.event_id == "iter001-public-substrate-verdict-v1"
    )
    current_source = legacy_source.model_copy(
        update={
            "schema_version": "daniel.research-memory.v2",
            "mission_id": "inbar",
            "sequence": sequence + 1,
            "event_id": "fixture-current-source-verdict",
            "source_commit": subject_commit,
            "evidence": (source_ref,),
            "links": {
                handoff_module._CURRENT_SOURCE_CORRECTION_LINK: (
                    handoff_module._SOURCE_VERDICT_EVENT_ID
                )
            },
            "summary": handoff_module._CURRENT_SOURCE_SUMMARY,
            "payload": {
                **legacy_source.payload,
                "compute_consequence": handoff_module._CURRENT_SOURCE_COMPUTE_CONSEQUENCE,
                "finding": handoff_module._CURRENT_SOURCE_FINDING,
                "product_wedge": handoff_module._CURRENT_SOURCE_PRODUCT_WEDGE,
                "reconnaissance_scope": handoff_module._CURRENT_SOURCE_RECONNAISSANCE_SCOPE,
                "external_evidence_status": (
                    handoff_module._CURRENT_SOURCE_EXTERNAL_EVIDENCE_STATUS
                ),
                "admissibility_boundary": handoff_module._CURRENT_SOURCE_ADMISSIBILITY_BOUNDARY,
                "source_architecture": list(handoff_module._CURRENT_SOURCE_ARCHITECTURE),
            },
        }
    )
    checkpoint = checkpoint_template.model_copy(
        update={
            "sequence": sequence + 2,
            "event_id": "fixture-v2-checkpoint",
            "stage": handoff_module._RECOVERY_STAGE,
            "source_commit": subject_commit,
            "evidence": (source_ref, verifier_ref),
            "payload": {
                "action": handoff_module.RECOVERY_CHECKPOINT_ACTION,
                "authority_effect": handoff_module.RECOVERY_CHECKPOINT_AUTHORITY_EFFECT,
                "handoff_contract": handoff_module._RECOVERY_CHECKPOINT_CONTRACT_V2,
                "implementation_commit": subject_commit,
                "outcome": handoff_module.RECOVERY_CHECKPOINT_OUTCOME,
                "validation_receipt": {
                    "receipt_id": receipt_id,
                    "path": receipt_path.relative_to(repo).as_posix(),
                    "git_commit": evidence_commit,
                    "sha256": sha256_bytes(receipt_bytes),
                    "bytes": len(receipt_bytes),
                    "media_type": handoff_module._VALIDATION_RECEIPT_MEDIA_TYPE,
                },
            },
        }
    )
    handoff = handoff_template.model_copy(
        update={
            "sequence": sequence + 3,
            "event_id": "fixture-v2-handoff",
            "stage": handoff_module._RECOVERY_STAGE,
            "source_commit": subject_commit,
            "evidence": (source_ref,),
            "links": {
                "checkpoint": checkpoint.event_id,
                "engine_boundary": handoff_module._ENGINE_BOUNDARY_EVENT_ID,
                "source_verdict": current_source.event_id,
            },
            "payload": {
                "forbidden_until_activation": list(handoff_module._CANONICAL_FORBIDDEN_ACTIONS),
                "handoff_contract": handoff_module._RECOVERY_HANDOFF_CONTRACT,
                "next_action": handoff_module.RECOVERY_HANDOFF_NEXT_ACTION,
                "remaining_gates": list(handoff_module._CANONICAL_REMAINING_GATES),
                "state": handoff_module.RECOVERY_HANDOFF_STATE,
            },
        }
    )
    checkpoint_payload = handoff_module._parse_payload(
        handoff_module._CheckpointPayload,
        checkpoint.payload,
        "implementation checkpoint",
    )
    assert isinstance(checkpoint_payload, handoff_module._CheckpointPayload)
    return SimpleNamespace(
        checkpoint=checkpoint,
        checkpoint_payload=checkpoint_payload,
        current_source=current_source,
        evidence_commit=evidence_commit,
        handoff=handoff,
        receipt=receipt,
        receipt_path=receipt_path,
        records=(*records, current_source, checkpoint, handoff),
        subject_commit=subject_commit,
    )


def _verify_v2_context(
    repo: Path,
    context: SimpleNamespace,
    report: MissionValidation | None = None,
) -> handoff_module._VerifiedValidationReceipt:
    handoff_payload = handoff_module._parse_payload(
        handoff_module._HandoffPayload,
        context.handoff.payload,
        "handoff",
    )
    assert isinstance(handoff_payload, handoff_module._HandoffPayload)
    handoff_module._validate_recovery_contract(
        context.handoff,
        context.checkpoint,
        handoff_payload,
        context.checkpoint_payload,
    )
    return handoff_module._verify_checkpoint_v2_receipt(
        repo,
        context.checkpoint,
        context.checkpoint_payload,
        report or _mission_report(),
    )


def test_checkpoint_v2_recomputes_committed_validation_and_renders_same_operator_scope(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _v2_validation_context(handoff_repo, memory_records)

    verified = _verify_v2_context(handoff_repo, context)
    assert verified.receipt.receipt_id == "validation.fixture.v2"
    assert verified.evidence_commit == context.evidence_commit
    assert len(verified.artifact_bindings) == 18

    _install_verified_dependencies(monkeypatch, context.records)
    document = render_handoff(handoff_repo).decode("utf-8")
    assert "## Same-operator engineering validation" in document
    assert "11 passed, 0 failed, 0 errors, 0 skipped" in document
    assert "Recomputed statement-plus-branch coverage: 95.00 percent" in document
    assert "Independent attestation: `false`" in document
    assert "Scientific result: `not_evaluated`" in document
    assert "Authority effect: `none`" in document
    assert "Bundle integrity does not prove command execution." in document
    assert "Reconnaissance scope: `dated_enumerated_non_systematic`" in document
    assert "External evidence status: `not_independently_reconstructible`" in document
    assert handoff_module._CURRENT_SOURCE_ADMISSIBILITY_BOUNDARY in document


def test_frozen_pytest_plan_executes_xfail_cases_normally(tmp_path: Path) -> None:
    plan = dict(handoff_module._expected_validation_plan("validation.fixture.v2"))
    assert "--runxfail" in plan["pytest-cov"]

    test_file = tmp_path / "test_xfail_mask.py"
    test_file.write_text(
        "import pytest\n\n"
        "pytestmark = pytest.mark.xfail(strict=False)\n\n"
        "def test_masked_failure():\n"
        "    assert False\n\n"
        "def test_masked_pass():\n"
        "    assert True\n",
        encoding="utf-8",
    )
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("COV_CORE_")
    }
    environment.pop("PYTEST_ADDOPTS", None)
    result = subprocess.run(  # noqa: S603 - test launches the current pinned interpreter
        [sys.executable, "-m", "pytest", "-q", "--runxfail", str(test_file)],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        env=environment,
        text=True,
        timeout=30,
    )

    assert result.returncode == 1
    assert "1 failed, 1 passed" in result.stdout


def test_legacy_recovery_seed_is_stable_when_an_explicit_v2_tail_is_latest(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
) -> None:
    context = _v2_validation_context(handoff_repo, memory_records)
    checkpoint, handoff = _selected_recovery_records(context.records)

    assert checkpoint.event_id == context.checkpoint.event_id
    assert handoff.event_id == context.handoff.event_id
    assert checkpoint.payload["handoff_contract"] == handoff_module._RECOVERY_CHECKPOINT_CONTRACT_V2
    assert "validation" not in checkpoint.payload
    assert _legacy_recovery_memory(context.records) == memory_records


def test_checkpoint_v2_rejects_self_report_and_lineage_counterexamples(
    tmp_path: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
) -> None:
    counterexamples = (
        (
            {"plan_override": ("uv-lock-check", ("uv", "lock"))},
            "command plan differs",
        ),
        ({"overlap_steps": True}, "overlap or are chronologically reordered"),
        ({"executable_artifact": True}, "tree entry is invalid"),
        (
            {"extra_evidence_path": "evidence/validation/validation.fixture.v2/unlisted.txt"},
            "directory contains an unlisted artifact",
        ),
        ({"credential_artifact": True}, "credential signature"),
        ({"extra_evidence_path": "unexpected-validation-commit-path.txt"}, "paths outside"),
        ({"preexisting_validation_file": True}, "directory contains an unlisted artifact"),
        ({"insert_parent_commit": True}, "single-parent child"),
        ({"noncanonical_receipt": True}, "not canonical JSON"),
        ({"pytest_counts": (3, 0, 0, 0)}, "test counts do not follow"),
        ({"coverage_observation": (10, 10, 10, 10)}, "coverage counts do not follow"),
        (
            {"coverage_paths_override": ("src/fieldtrue/second.py",)},
            "coverage file inventory differs",
        ),
        ({"empty_step_logs": True}, "validation step has no recorded output"),
        ({"executable_source": True}, "not a regular 100644 blob"),
        ({"actor_id": "different-producer"}, "same-operator binding is invalid"),
        (
            {"mission_check_ids": handoff_module._EXPECTED_MISSION_CHECK_IDS[:-1]},
            "mission observation differs",
        ),
    )
    for index, (context_options, message) in enumerate(counterexamples):
        repo = _build_handoff_repo(tmp_path / f"counterexample-{index}")
        context = _v2_validation_context(repo, memory_records, **context_options)
        with pytest.raises(HandoffError, match=message):
            _verify_v2_context(repo, context)


def test_checkpoint_v2_rejects_current_artifact_drift(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
) -> None:
    context = _v2_validation_context(handoff_repo, memory_records)
    artifact = handoff_repo / "evidence/validation/validation.fixture.v2/ruff-check.stdout.txt"
    artifact.write_bytes(artifact.read_bytes() + b"changed after commit\n")

    with pytest.raises(HandoffError, match="differs from its receipt binding"):
        _verify_v2_context(handoff_repo, context)


def _commit_v2_finalization(
    repo: Path,
    *,
    executable_path: str | None = None,
    extra_path: str | None = None,
    rewrite_memory: bool = False,
) -> str:
    memory_path = repo / handoff_module._MEMORY_PATH
    if rewrite_memory:
        memory_path.write_text("rewritten final memory\n", encoding="utf-8")
    else:
        memory_path.write_bytes(memory_path.read_bytes() + b"final memory\n")
    (repo / handoff_module._HANDOFF_PATH).write_text("# Final handoff\n", encoding="utf-8")
    if extra_path is not None:
        (repo / extra_path).write_text("unexpected finalization content\n", encoding="utf-8")
    _git(repo, "add", "-A")
    if executable_path is not None:
        _git(repo, "update-index", "--chmod=+x", executable_path)
    _git(repo, "commit", "--quiet", "-m", "finalize handoff")
    return _git(repo, "rev-parse", "HEAD")


def _commit_tree_with_parents(
    repo: Path,
    *,
    tree_commit: str,
    parents: tuple[str, ...],
) -> str:
    tree = _git(repo, "rev-parse", "--verify", f"{tree_commit}^{{tree}}")
    arguments = ["commit-tree", tree]
    for parent in parents:
        arguments.extend(("-p", parent))
    arguments.extend(("-m", "integration wrapper fixture"))
    commit = _git(repo, *arguments)
    _git(repo, "reset", "--hard", commit)
    return commit


def test_checkpoint_v2_accepts_only_prospective_b_or_exact_final_c(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
) -> None:
    context = _v2_validation_context(handoff_repo, memory_records)
    git = handoff_module.trusted_repository_git(
        handoff_repo,
        handoff_module.TRUSTED_GIT_PATH,
    )
    assert handoff_module._verify_v2_finalization_topology(
        handoff_repo, git, context.evidence_commit
    )

    _commit_v2_finalization(handoff_repo)

    assert not handoff_module._verify_v2_finalization_topology(
        handoff_repo, git, context.evidence_commit
    )
    _verify_v2_context(handoff_repo, context)


def test_checkpoint_v2_accepts_one_transparent_integration_wrapper(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
) -> None:
    context = _v2_validation_context(
        handoff_repo,
        memory_records,
        prior_integration_base=True,
    )
    git = handoff_module.trusted_repository_git(
        handoff_repo,
        handoff_module.TRUSTED_GIT_PATH,
    )
    final_commit = _commit_v2_finalization(handoff_repo)
    integration_base = _git(
        handoff_repo,
        "rev-parse",
        "--verify",
        f"{context.subject_commit}^",
    )
    _commit_tree_with_parents(
        handoff_repo,
        tree_commit=final_commit,
        parents=(integration_base, final_commit),
    )

    assert not handoff_module._verify_v2_finalization_topology(
        handoff_repo,
        git,
        context.evidence_commit,
    )
    _verify_v2_context(handoff_repo, context)
    handoff_module._verify_v2_checkout_state(
        handoff_repo,
        git,
        context.evidence_commit,
    )


def test_checkpoint_v2_rejects_nontransparent_integration_wrappers(
    tmp_path: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
) -> None:
    scenarios = (
        ("reversed-parents", "proper ancestor"),
        ("three-parents", "one transparent two-parent"),
        ("different-tree", "tree differs"),
        ("unrelated-first-parent", "proper ancestor"),
        ("evidence-first-parent", "proper ancestor"),
        ("nested-wrapper", "single-parent child"),
    )
    for scenario, message in scenarios:
        repo = _build_handoff_repo(tmp_path / scenario)
        context = _v2_validation_context(repo, memory_records)
        final_commit = _commit_v2_finalization(repo)
        if scenario == "reversed-parents":
            parents = (final_commit, context.subject_commit)
            tree_commit = final_commit
        elif scenario == "three-parents":
            parents = (
                context.subject_commit,
                final_commit,
                context.evidence_commit,
            )
            tree_commit = final_commit
        elif scenario == "different-tree":
            parents = (context.subject_commit, final_commit)
            tree_commit = context.evidence_commit
        elif scenario == "unrelated-first-parent":
            final_tree = _git(repo, "rev-parse", "--verify", f"{final_commit}^{{tree}}")
            unrelated = _git(
                repo,
                "commit-tree",
                final_tree,
                "-m",
                "unrelated root fixture",
            )
            parents = (unrelated, final_commit)
            tree_commit = final_commit
        elif scenario == "evidence-first-parent":
            parents = (context.evidence_commit, final_commit)
            tree_commit = final_commit
        else:
            wrapper = _commit_tree_with_parents(
                repo,
                tree_commit=final_commit,
                parents=(context.subject_commit, final_commit),
            )
            parents = (context.subject_commit, wrapper)
            tree_commit = wrapper
        _commit_tree_with_parents(
            repo,
            tree_commit=tree_commit,
            parents=parents,
        )

        with pytest.raises(HandoffError, match=message):
            _verify_v2_context(repo, context)


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"rewrite_memory": True}, "not a strict byte-prefix append"),
        (
            {"executable_path": handoff_module._MEMORY_PATH},
            "tree entry is invalid",
        ),
        (
            {"executable_path": handoff_module._HANDOFF_PATH},
            "tree entry is invalid",
        ),
    ],
)
def test_checkpoint_v2_rejects_rewritten_or_executable_finalization(
    tmp_path: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    options: dict[str, object],
    message: str,
) -> None:
    repo = _build_handoff_repo(tmp_path / message.replace(" ", "-"))
    context = _v2_validation_context(repo, memory_records)
    _commit_v2_finalization(repo, **options)  # type: ignore[arg-type]

    with pytest.raises(HandoffError, match=message):
        _verify_v2_context(repo, context)


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"rewrite_memory": True}, "not a strict byte-prefix append"),
        (
            {"executable_path": handoff_module._MEMORY_PATH},
            "tree entry is invalid",
        ),
        (
            {"executable_path": handoff_module._HANDOFF_PATH},
            "tree entry is invalid",
        ),
        (
            {"extra_path": "unexpected-wrapper-content.txt"},
            "does not contain exactly",
        ),
    ],
)
def test_checkpoint_v2_wrapper_preserves_finalization_controls(
    tmp_path: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    options: dict[str, object],
    message: str,
) -> None:
    repo = _build_handoff_repo(tmp_path / f"wrapper-{message.replace(' ', '-')}")
    context = _v2_validation_context(repo, memory_records)
    final_commit = _commit_v2_finalization(repo, **options)  # type: ignore[arg-type]
    _commit_tree_with_parents(
        repo,
        tree_commit=final_commit,
        parents=(context.subject_commit, final_commit),
    )

    with pytest.raises(HandoffError, match=message):
        _verify_v2_context(repo, context)


def test_handoff_check_requires_exact_clean_v2_finalization(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _v2_validation_context(
        handoff_repo,
        memory_records,
        prior_integration_base=True,
    )
    _install_verified_dependencies(monkeypatch, context.records)
    monkeypatch.setattr(
        handoff_module,
        "_v2_evidence_commit_from_memory",
        lambda _data: context.evidence_commit,
    )
    memory_path = handoff_repo / handoff_module._MEMORY_PATH
    memory_path.write_bytes(memory_path.read_bytes() + b"finalized v2 memory\n")
    write_handoff(handoff_repo)

    with pytest.raises(HandoffError, match="final handoff commit has not been created"):
        check_handoff(handoff_repo)

    _git(
        handoff_repo,
        "add",
        handoff_module._MEMORY_PATH,
        handoff_module._HANDOFF_PATH,
    )
    _git(handoff_repo, "commit", "--quiet", "-m", "finalize v2 handoff")
    final_commit = _git(handoff_repo, "rev-parse", "HEAD")

    integration_base = _git(
        handoff_repo,
        "rev-parse",
        "--verify",
        f"{context.subject_commit}^",
    )
    _commit_tree_with_parents(
        handoff_repo,
        tree_commit=final_commit,
        parents=(integration_base, final_commit),
    )

    check_handoff(handoff_repo)

    original_head = handoff_module._git_head
    head_reads = 0

    def changing_head(repo: Path, git: str) -> str:
        nonlocal head_reads
        head_reads += 1
        if head_reads == 3:
            return "0" * 40
        return original_head(repo, git)

    monkeypatch.setattr(handoff_module, "_git_head", changing_head)
    with pytest.raises(HandoffError):
        check_handoff(handoff_repo)


def test_checkpoint_v2_rejects_extra_finalization_content_and_later_source_commit(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
) -> None:
    context = _v2_validation_context(handoff_repo, memory_records)
    _commit_v2_finalization(handoff_repo, extra_path="later-source.txt")

    with pytest.raises(HandoffError, match="does not contain exactly"):
        _verify_v2_context(handoff_repo, context)

    _git(handoff_repo, "reset", "--soft", "HEAD^")
    _git(handoff_repo, "reset", "--", "later-source.txt")
    (handoff_repo / "later-source.txt").unlink()
    _git(handoff_repo, "commit", "--quiet", "-m", "finalize handoff")
    (handoff_repo / "README.md").write_text("later source revision\n", encoding="utf-8")
    _git(handoff_repo, "add", "README.md")
    _git(handoff_repo, "commit", "--quiet", "-m", "later source commit")

    with pytest.raises(HandoffError, match="not the single-parent child"):
        _verify_v2_context(handoff_repo, context)


def test_checkpoint_v2_checkout_requires_clean_c_and_bounds_prospective_changes(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
) -> None:
    context = _v2_validation_context(handoff_repo, memory_records)
    git = handoff_module.trusted_repository_git(
        handoff_repo,
        handoff_module.TRUSTED_GIT_PATH,
    )
    memory_path = handoff_repo / handoff_module._MEMORY_PATH
    memory_path.write_bytes(memory_path.read_bytes() + b"prospective final memory\n")
    handoff_module._verify_v2_checkout_state(handoff_repo, git, context.evidence_commit)
    (handoff_repo / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")
    with pytest.raises(HandoffError, match="changes outside"):
        handoff_module._verify_v2_checkout_state(handoff_repo, git, context.evidence_commit)

    (handoff_repo / "unexpected.txt").unlink()
    _commit_v2_finalization(handoff_repo)
    handoff_module._verify_v2_checkout_state(handoff_repo, git, context.evidence_commit)
    (handoff_repo / "README.md").write_text("dirty final checkout\n", encoding="utf-8")
    with pytest.raises(HandoffError, match="checkout is not clean"):
        handoff_module._verify_v2_checkout_state(handoff_repo, git, context.evidence_commit)


@pytest.mark.parametrize("dirty_kind", ["unstaged", "staged", "untracked"])
def test_checkpoint_v2_wrapper_requires_clean_checkout(
    tmp_path: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    dirty_kind: str,
) -> None:
    repo = _build_handoff_repo(tmp_path / f"wrapper-dirty-{dirty_kind}")
    context = _v2_validation_context(repo, memory_records)
    git = handoff_module.trusted_repository_git(
        repo,
        handoff_module.TRUSTED_GIT_PATH,
    )
    final_commit = _commit_v2_finalization(repo)
    _commit_tree_with_parents(
        repo,
        tree_commit=final_commit,
        parents=(context.subject_commit, final_commit),
    )
    if dirty_kind == "untracked":
        (repo / "untracked-wrapper-state.txt").write_text(
            "untracked\n",
            encoding="utf-8",
        )
    else:
        (repo / "README.md").write_text("dirty wrapper state\n", encoding="utf-8")
        if dirty_kind == "staged":
            _git(repo, "add", "README.md")

    with pytest.raises(HandoffError, match="checkout is not clean"):
        handoff_module._verify_v2_checkout_state(repo, git, context.evidence_commit)


def test_recovery_materialization_rejects_ignored_and_untracked_regular_files(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "tracked-recovery-source"
    repo.mkdir()
    (repo / ".gitignore").write_text("*.pyc\n", encoding="utf-8")
    (repo / "README.md").write_text("# Tracked recovery fixture\n", encoding="utf-8")
    package = repo / "src" / "fieldtrue"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text('"""Fixture package."""\n', encoding="utf-8")
    memory = repo / handoff_module._MEMORY_PATH
    memory.parent.mkdir(parents=True)
    memory.write_text("fixture memory\n", encoding="utf-8")
    _git(repo, "init", "--quiet", "--initial-branch=main")
    _git(repo, "config", "user.name", "Recovery Binding Test")
    _git(repo, "config", "user.email", "recovery-binding@example.invalid")
    _git(repo, "add", "-A")
    _git(repo, "commit", "--quiet", "-m", "freeze recovery source")

    git = handoff_module.trusted_repository_git(repo, handoff_module.TRUSTED_GIT_PATH)
    head = handoff_module._git_head(repo, git)
    clean_manifest = handoff_module._recovery_manifest(repo)
    handoff_module._verify_recovery_manifest_git_binding(repo, git, head, clean_manifest)
    memory_bytes, memory_metadata = handoff_module._read_regular_file_snapshot(
        repo,
        handoff_module._MEMORY_PATH,
        handoff_module._MEMORY_PATH,
    )

    ignored_bytecode = repo / "src" / "pydantic.pyc"
    ignored_bytecode.write_bytes(b"ignored dependency shadow\n")
    ignored_manifest = handoff_module._recovery_manifest(repo)
    assert not handoff_module._git_worktree_changed_paths(repo, git)
    assert any(item.path == "src/pydantic.pyc" for item in ignored_manifest.files)
    with pytest.raises(HandoffError, match="differs from the selected committed tree"):
        handoff_module._materialize_repository_snapshot(
            repo,
            tmp_path / "ignored-snapshot",
            git=git,
            head=head,
            recovery_manifest=ignored_manifest,
            memory_bytes=memory_bytes,
            memory_metadata=memory_metadata,
        )
    assert not (tmp_path / "ignored-snapshot").exists()

    ignored_bytecode.unlink()
    untracked = repo / "untracked.txt"
    untracked.write_text("untracked recovery input\n", encoding="utf-8")
    untracked_manifest = handoff_module._recovery_manifest(repo)
    assert handoff_module._git_worktree_changed_paths(repo, git) == frozenset({"untracked.txt"})
    with pytest.raises(HandoffError, match="differs from the selected committed tree"):
        handoff_module._verify_recovery_manifest_git_binding(
            repo,
            git,
            head,
            untracked_manifest,
        )

    untracked.unlink()
    readme = repo / "README.md"
    readme.write_bytes(readme.read_bytes() + b"dirty tracked bytes\n")
    dirty_tracked_manifest = handoff_module._recovery_manifest(repo)
    assert handoff_module._git_worktree_changed_paths(repo, git) == frozenset({"README.md"})
    with pytest.raises(HandoffError, match="content differs from the selected committed tree"):
        handoff_module._verify_recovery_manifest_git_binding(
            repo,
            git,
            head,
            dirty_tracked_manifest,
        )


def test_git_batch_blob_bindings_verify_exact_binary_frames(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_blob = b"first\x00blob\n"
    second_blob = b"\xffsecond blob"
    first_frame = b"blob " + str(len(first_blob)).encode("ascii") + b"\x00" + first_blob
    second_frame = b"blob " + str(len(second_blob)).encode("ascii") + b"\x00" + second_blob
    first_id = hashlib.sha1(first_frame, usedforsecurity=False).hexdigest()
    second_id = hashlib.sha256(second_frame).hexdigest()
    metadata = (f"{first_id} blob {len(first_blob)}\n{second_id} blob {len(second_blob)}\n").encode(
        "ascii"
    )
    content = (
        f"{first_id} blob {len(first_blob)}\n".encode("ascii")
        + first_blob
        + b"\n"
        + f"{second_id} blob {len(second_blob)}\n".encode("ascii")
        + second_blob
        + b"\n"
    )
    calls: list[dict[str, object]] = []

    def bounded_output(
        _repo_root: Path,
        _git: str,
        arguments: tuple[str, ...],
        *,
        maximum_bytes: int,
        label: str,
        input_bytes: bytes | None = None,
    ) -> bytes:
        calls.append(
            {
                "arguments": arguments,
                "maximum_bytes": maximum_bytes,
                "label": label,
                "input_bytes": input_bytes,
            }
        )
        return metadata if arguments[-1] == "--batch-check" else content

    monkeypatch.setattr(handoff_module, "_git_bounded_output", bounded_output)

    assert handoff_module._git_batch_blob_bindings(
        tmp_path,
        "/trusted/git",
        (first_id, second_id),
    ) == {
        first_id: (len(first_blob), sha256_bytes(first_blob)),
        second_id: (len(second_blob), sha256_bytes(second_blob)),
    }
    request = f"{first_id}\n{second_id}\n".encode("ascii")
    assert calls == [
        {
            "arguments": ("--no-replace-objects", "cat-file", "--batch-check"),
            "maximum_bytes": handoff_module._MAX_GIT_METADATA_BYTES,
            "label": "tracked recovery blob metadata batch",
            "input_bytes": request,
        },
        {
            "arguments": ("--no-replace-objects", "cat-file", "--batch"),
            "maximum_bytes": len(content),
            "label": "tracked recovery blob content batch",
            "input_bytes": request,
        },
    ]


def test_git_bounded_output_streams_input_and_enforces_live_output_cap(tmp_path: Path) -> None:
    program = "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read()[::-1])"
    assert (
        handoff_module._git_bounded_output(
            tmp_path,
            sys.executable,
            ("-c", program),
            maximum_bytes=4,
            label="bounded subprocess fixture",
            input_bytes=b"a\x00bc",
        )
        == b"cb\x00a"
    )

    with pytest.raises(HandoffError, match="exceeds its verification bound"):
        handoff_module._git_bounded_output(
            tmp_path,
            sys.executable,
            (
                "-c",
                "import os,threading;os.write(1,b'1234');threading.Event().wait()",
            ),
            maximum_bytes=3,
            label="bounded subprocess fixture",
        )
    with pytest.raises(HandoffError, match="invalid verification bound"):
        handoff_module._git_bounded_output(
            tmp_path,
            sys.executable,
            ("-c", "raise SystemExit(0)"),
            maximum_bytes=-1,
            label="bounded subprocess fixture",
        )


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        ("missing", "header is invalid"),
        ("wrong-object", "header is invalid"),
        ("non-blob", "header is invalid"),
        ("noncanonical-size", "size is invalid"),
        ("oversized", "per-file limit"),
        ("metadata-truncated", "metadata batch is truncated"),
        ("content-wrong-object", "header is invalid"),
        ("size-changed", "size changed"),
        ("truncated", "content batch is truncated"),
        ("bad-frame", "framing is invalid"),
        ("body-mismatch", "does not match its object ID"),
        ("trailing", "trailing output"),
    ],
)
def test_git_batch_blob_bindings_reject_malformed_output(
    failure: str,
    message: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    object_id = "c1b0730e0133447badcfd47fd144e254807b06e1"
    valid_metadata = f"{object_id} blob 1\n".encode("ascii")
    outputs = {
        "missing": (f"{object_id} missing\n".encode("ascii"), b""),
        "wrong-object": (f"{'2' * 40} blob 1\n".encode("ascii"), b""),
        "non-blob": (f"{object_id} tree 1\n".encode("ascii"), b""),
        "noncanonical-size": (f"{object_id} blob 01\n".encode("ascii"), b""),
        "oversized": (
            f"{object_id} blob {handoff_module._MAX_INPUT_BYTES + 1}\n".encode("ascii"),
            b"",
        ),
        "metadata-truncated": (f"{object_id} blob 1".encode("ascii"), b""),
        "content-wrong-object": (
            valid_metadata,
            f"{'2' * 40} blob 1\nx\n".encode("ascii"),
        ),
        "size-changed": (
            valid_metadata,
            f"{object_id} blob 2\nxx\n".encode("ascii"),
        ),
        "truncated": (
            f"{object_id} blob 2\n".encode("ascii"),
            f"{object_id} blob 2\nx".encode("ascii"),
        ),
        "bad-frame": (valid_metadata, f"{object_id} blob 1\nx!".encode("ascii")),
        "body-mismatch": (valid_metadata, f"{object_id} blob 1\ny\n".encode("ascii")),
        "trailing": (
            valid_metadata,
            f"{object_id} blob 1\nx\nextra".encode("ascii"),
        ),
    }

    def bounded_output(
        _repo_root: Path,
        _git: str,
        arguments: tuple[str, ...],
        **_kwargs: object,
    ) -> bytes:
        metadata, content = outputs[failure]
        return metadata if arguments[-1] == "--batch-check" else content

    monkeypatch.setattr(handoff_module, "_git_bounded_output", bounded_output)

    with pytest.raises(HandoffError, match=message):
        handoff_module._git_batch_blob_bindings(tmp_path, "/trusted/git", (object_id,))


def test_git_blob_object_id_matches_git_sha1_and_sha256() -> None:
    assert handoff_module._git_blob_object_id(b"", 40) == "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
    assert (
        handoff_module._git_blob_object_id(b"", 64)
        == "473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813"
    )
    with pytest.raises(HandoffError, match="object ID length is invalid"):
        handoff_module._git_blob_object_id(b"", 32)


def test_git_batch_blob_bindings_reject_ambiguous_requests(tmp_path: Path) -> None:
    object_id = "1" * 40

    with pytest.raises(HandoffError, match="empty or ambiguous"):
        handoff_module._git_batch_blob_bindings(tmp_path, "/trusted/git", ())
    with pytest.raises(HandoffError, match="empty or ambiguous"):
        handoff_module._git_batch_blob_bindings(
            tmp_path,
            "/trusted/git",
            (object_id, object_id),
        )
    with pytest.raises(HandoffError, match="invalid object ID"):
        handoff_module._git_batch_blob_bindings(tmp_path, "/trusted/git", ("g" * 40,))


def test_git_recovery_binding_counts_duplicate_blob_paths_toward_total_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    object_id = "1" * 40
    inventory = (
        f"100644 blob {object_id}\tfirst.txt".encode("ascii")
        + b"\x00"
        + f"100644 blob {object_id}\tsecond.txt".encode("ascii")
        + b"\x00"
    )
    monkeypatch.setattr(
        handoff_module,
        "_git_bounded_output",
        lambda *_args, **_kwargs: inventory,
    )
    monkeypatch.setattr(
        handoff_module,
        "_git_batch_blob_bindings",
        lambda *_args, **_kwargs: {object_id: (2, sha256_bytes(b"xx"))},
    )
    monkeypatch.setattr(handoff_module, "_MAX_RECOVERY_INPUT_BYTES", 3)

    with pytest.raises(HandoffError, match="blobs exceed the total input limit"):
        handoff_module._git_eligible_recovery_files(tmp_path, "/trusted/git", "2" * 40)


def test_git_batch_blob_bindings_enforce_request_and_total_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_id = "1" * 40
    second_id = "2" * 40
    metadata = f"{first_id} blob 2\n{second_id} blob 2\n".encode("ascii")
    monkeypatch.setattr(
        handoff_module,
        "_git_bounded_output",
        lambda *_args, **_kwargs: metadata,
    )
    monkeypatch.setattr(handoff_module, "_MAX_RECOVERY_INPUT_BYTES", 3)

    with pytest.raises(HandoffError, match="batch exceeds the total input limit"):
        handoff_module._git_batch_blob_bindings(
            tmp_path,
            "/trusted/git",
            (first_id, second_id),
        )

    monkeypatch.setattr(handoff_module, "_MAX_GIT_METADATA_BYTES", len(first_id))
    with pytest.raises(HandoffError, match="request exceeds its verification bound"):
        handoff_module._git_batch_blob_bindings(tmp_path, "/trusted/git", (first_id,))


def test_validation_lineage_path_inventory_disables_rename_detection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_arguments: list[tuple[str, ...]] = []

    def bounded_output(
        _repo_root: Path,
        _git: str,
        arguments: tuple[str, ...],
        *,
        maximum_bytes: int,
        label: str,
    ) -> bytes:
        assert maximum_bytes == handoff_module._MAX_GIT_METADATA_BYTES
        assert label == "validation commit path inventory"
        observed_arguments.append(arguments)
        return b"new-name.txt\0old-name.txt\0"

    monkeypatch.setattr(handoff_module, "_git_bounded_output", bounded_output)

    assert handoff_module._git_changed_paths(
        tmp_path,
        str(handoff_module.TRUSTED_GIT_PATH),
        "1" * 40,
        "2" * 40,
    ) == frozenset({"new-name.txt", "old-name.txt"})
    assert observed_arguments == [
        (
            "diff-tree",
            "--no-commit-id",
            "--no-renames",
            "--name-only",
            "-r",
            "-z",
            "1" * 40,
            "2" * 40,
        )
    ]


@pytest.mark.parametrize(
    "mutation",
    [
        "summary",
        "source_commit",
        "correction_link",
        "evidence_path",
        "evidence_sha",
        "evidence_access",
    ],
)
def test_checkpoint_v2_rejects_unbounded_current_source_verdict(
    mutation: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
) -> None:
    context = _v2_validation_context(handoff_repo, memory_records)
    source_record = context.current_source
    if mutation == "summary":
        source_record = source_record.model_copy(update={"summary": "Unsafe broad verdict."})
    elif mutation == "source_commit":
        source_record = source_record.model_copy(update={"source_commit": context.evidence_commit})
    elif mutation == "correction_link":
        source_record = source_record.model_copy(update={"links": {}})
    else:
        if mutation == "evidence_path":
            evidence_update: dict[str, object] = {"uri": "README.md"}
        elif mutation == "evidence_sha":
            evidence_update = {"sha256": "0" * 64}
        else:
            evidence_update = {"access": AccessClass.PUBLIC}
        evidence = source_record.evidence[0].model_copy(update=evidence_update)
        source_record = source_record.model_copy(update={"evidence": (evidence,)})
    source = handoff_module._parse_source_payload(source_record.payload)
    assert isinstance(source, handoff_module._CurrentSourceVerdictPayload)
    records = {
        record.event_id: record
        for record in (*context.records[:-3], source_record, context.checkpoint, context.handoff)
    }

    with pytest.raises(HandoffError, match=r"exact bounded correction|content-valid"):
        handoff_module._verify_current_source_verdict(
            handoff_repo,
            records,
            source_record,
            source,
            context.checkpoint_payload,
        )


def test_checkpoint_v2_rejects_current_source_audit_worktree_drift(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
) -> None:
    context = _v2_validation_context(handoff_repo, memory_records)
    audit = handoff_repo / handoff_module._CURRENT_SOURCE_AUDIT_PATH
    audit.write_bytes(audit.read_bytes() + b"uncommitted drift\n")
    source = handoff_module._parse_source_payload(context.current_source.payload)
    assert isinstance(source, handoff_module._CurrentSourceVerdictPayload)

    with pytest.raises(HandoffError, match="not content-valid at A"):
        handoff_module._verify_current_source_verdict(
            handoff_repo,
            {record.event_id: record for record in context.records},
            context.current_source,
            source,
            context.checkpoint_payload,
        )


def test_checkpoint_v2_rejects_receipt_evidence_ref_substitution(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
) -> None:
    context = _v2_validation_context(handoff_repo, memory_records)
    payload = {
        **context.checkpoint.payload,
        "validation_receipt": {
            **context.checkpoint.payload["validation_receipt"],
            "sha256": "0" * 64,
        },
    }
    checkpoint = context.checkpoint.model_copy(update={"payload": payload})
    parsed = handoff_module._parse_payload(
        handoff_module._CheckpointPayload,
        payload,
        "implementation checkpoint",
    )
    assert isinstance(parsed, handoff_module._CheckpointPayload)

    with pytest.raises(HandoffError, match="differs from its verifier evidence ref"):
        handoff_module._verify_checkpoint_v2_receipt(
            handoff_repo, checkpoint, parsed, _mission_report()
        )


def test_checkpoint_v2_rejects_live_mission_drift(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
) -> None:
    context = _v2_validation_context(handoff_repo, memory_records)

    with pytest.raises(HandoffError, match="mission observation differs"):
        _verify_v2_context(
            handoff_repo,
            context,
            _mission_report(extra_failures=("unexpected-check",)),
        )


@pytest.mark.parametrize(
    "junit",
    [
        (
            b'<?xml version="1.0"?><!DOCTYPE testsuites [<!ENTITY x "x">]>'
            b'<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0">'
            b'<testcase name="x">&x;</testcase></testsuite></testsuites>'
        ),
        (
            '<?xml version="1.0" encoding="utf-16"?>'
            '<!DOCTYPE testsuites [<!ENTITY x "tests.unit.test_control">]>'
            '<testsuites tests="1" failures="0" errors="0" skipped="0">'
            '<testsuite tests="1" failures="0" errors="0" skipped="0">'
            '<testcase classname="&x;" name="test_control" />'
            "</testsuite></testsuites>"
        ).encode("utf-16"),
        (
            b'<testsuites><testsuite tests="2" failures="0" errors="0" skipped="0">'
            b'<testcase name="x" /></testsuite></testsuites>'
        ),
        (
            b'<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0" '
            b'time="nan"><testcase name="x" /></testsuite></testsuites>'
        ),
        (
            b'<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0">'
            b'<testcase name="x"><failure /><failure /></testcase></testsuite></testsuites>'
        ),
    ],
)
def test_junit_recomputation_rejects_declarations_and_self_reported_totals(
    junit: bytes,
) -> None:
    with pytest.raises(HandoffError):
        handoff_module._recompute_junit(junit)


def test_junit_recomputation_derives_failure_and_error_outcomes() -> None:
    junit = (
        b'<testsuites tests="3" failures="1" errors="1" skipped="0" time="0.3" '
        b'disabled="0"><testsuite tests="3" failures="1" errors="1" skipped="0" '
        b'time="0.3"><testcase classname="fixture" name="pass" time="0.1" assertions="1" />'
        b'<testcase classname="fixture" name="fail" time="0.1"><failure /></testcase>'
        b'<testcase classname="fixture" name="error" time="0.1"><error /></testcase>'
        b"</testsuite></testsuites>"
    )

    assert handoff_module._recompute_junit(junit) == (1, 1, 1, 0)


def test_junit_recomputation_binds_registered_control_execution() -> None:
    nodes = _fixture_credibility_nodes()

    assert handoff_module._recompute_junit(
        _validation_junit_bytes(),
        required_nodes=nodes,
    ) == (11, 0, 0, 0)

    with pytest.raises(HandoffError, match="was not executed successfully"):
        handoff_module._recompute_junit(
            _validation_junit_bytes(),
            required_nodes=(*nodes, "tests/unit/test_missing.py::test_missing_control"),
        )


def test_junit_recomputation_rejects_skipped_registered_control_parameter() -> None:
    node_id = "tests/unit/test_control.py::test_registered_control"
    junit = (
        b'<testsuites tests="2" failures="0" errors="0" skipped="1" time="0.2">'
        b'<testsuite tests="2" failures="0" errors="0" skipped="1" time="0.2">'
        b'<testcase classname="tests.unit.test_control" '
        b'name="test_registered_control[positive]" time="0.1" />'
        b'<testcase classname="tests.unit.test_control" '
        b'name="test_registered_control[placebo]" time="0.1"><skipped /></testcase>'
        b"</testsuite></testsuites>"
    )

    with pytest.raises(HandoffError, match="was not executed successfully"):
        handoff_module._recompute_junit(junit, required_nodes=(node_id,))


@pytest.mark.parametrize(
    "junit",
    [
        b"not xml",
        b"<testsuites />",
        b'<testsuites><testsuite tests="0"><unknown /></testsuite></testsuites>',
        (
            b'<testsuites><testsuite tests="0" failures="0" errors="0" skipped="0">'
            b"</testsuite></testsuites>"
        ),
        (
            b'<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0">'
            b'<testcase name="x" time="not-a-number" /></testsuite></testsuites>'
        ),
        (
            b'<testsuites><testsuite tests="-1" failures="0" errors="0" skipped="0">'
            b'<testcase name="x" /></testsuite></testsuites>'
        ),
    ],
)
def test_junit_recomputation_rejects_malformed_structure_and_numerics(junit: bytes) -> None:
    with pytest.raises(HandoffError):
        handoff_module._recompute_junit(junit)


@pytest.mark.parametrize(
    "junit",
    [
        (
            b'<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0" '
            b'time="0.1"><testsuite tests="1" failures="0" errors="0" skipped="0" '
            b'time="0.1"><testcase classname="fixture" name="x" time="0.1" />'
            b"</testsuite></testsuite></testsuites>"
        ),
        (
            b'<testsuites><testsuite tests="2" failures="0" errors="0" skipped="0" '
            b'time="0.2"><testcase classname="fixture" name="x" time="0.1" />'
            b'<testcase classname="fixture" name="x" time="0.1" />'
            b"</testsuite></testsuites>"
        ),
        (
            b'<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0" '
            b'time="0.1"><testcase classname="" name="x" time="0.1" />'
            b"</testsuite></testsuites>"
        ),
        (
            b'<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0" '
            b'time="0.1"><testcase classname="fixture" name="x" />'
            b"</testsuite></testsuites>"
        ),
    ],
)
def test_junit_recomputation_requires_flat_unique_timed_pytest_cases(junit: bytes) -> None:
    with pytest.raises(HandoffError):
        handoff_module._recompute_junit(junit)


def test_coverage_recomputation_rejects_duplicate_and_self_reported_counts() -> None:
    coverage = json.loads(_validation_coverage_bytes())
    coverage["files"]["src/fieldtrue/fixture.py"]["executed_lines"].append(1)
    with pytest.raises(HandoffError, match="contains duplicates"):
        handoff_module._recompute_coverage(canonical_json_pretty(coverage))

    coverage = json.loads(_validation_coverage_bytes())
    coverage["totals"]["covered_lines"] = 9
    with pytest.raises(HandoffError, match="does not follow from raw observations"):
        handoff_module._recompute_coverage(canonical_json_pretty(coverage))


def test_coverage_recomputation_rejects_malformed_raw_evidence() -> None:
    for malformed in (b"{", b"[]", b'{"meta":{},"meta":{}}'):
        with pytest.raises(HandoffError):
            handoff_module._recompute_coverage(malformed)

    def document() -> dict[str, object]:
        return json.loads(_validation_coverage_bytes())

    coverage = document()
    coverage["meta"]["branch_coverage"] = False
    with pytest.raises(HandoffError, match="not branch-aware"):
        handoff_module._recompute_coverage(canonical_json_pretty(coverage))

    coverage = document()
    coverage["files"] = {}
    with pytest.raises(HandoffError, match="no file observations"):
        handoff_module._recompute_coverage(canonical_json_pretty(coverage))

    coverage = document()
    file_observation = coverage["files"].pop("src/fieldtrue/fixture.py")
    coverage["files"][""] = file_observation
    with pytest.raises(HandoffError, match="file observation is invalid"):
        handoff_module._recompute_coverage(canonical_json_pretty(coverage))

    coverage = document()
    file_observation = coverage["files"].pop("src/fieldtrue/fixture.py")
    coverage["files"]["src/fieldtrue/../escape.py"] = file_observation
    with pytest.raises(HandoffError, match="not a normalized repository path"):
        handoff_module._recompute_coverage(canonical_json_pretty(coverage))

    coverage = document()
    file_observation = coverage["files"]["src/fieldtrue/fixture.py"]
    file_observation["executed_lines"] = "not-a-list"
    with pytest.raises(HandoffError, match="executed_lines is invalid"):
        handoff_module._recompute_coverage(canonical_json_pretty(coverage))

    coverage = document()
    file_observation = coverage["files"]["src/fieldtrue/fixture.py"]
    file_observation["missing_lines"].append(1)
    with pytest.raises(HandoffError, match="line observations overlap"):
        handoff_module._recompute_coverage(canonical_json_pretty(coverage))

    coverage = document()
    file_observation = coverage["files"]["src/fieldtrue/fixture.py"]
    file_observation["executed_branches"] = "not-a-list"
    with pytest.raises(HandoffError, match="executed_branches is invalid"):
        handoff_module._recompute_coverage(canonical_json_pretty(coverage))

    coverage = document()
    file_observation = coverage["files"]["src/fieldtrue/fixture.py"]
    file_observation["executed_branches"] = [[1]]
    with pytest.raises(HandoffError, match="executed_branches is invalid"):
        handoff_module._recompute_coverage(canonical_json_pretty(coverage))

    coverage = document()
    file_observation = coverage["files"]["src/fieldtrue/fixture.py"]
    file_observation["executed_branches"].append([1, 2])
    with pytest.raises(HandoffError, match="executed_branches contains duplicates"):
        handoff_module._recompute_coverage(canonical_json_pretty(coverage))

    coverage = document()
    file_observation = coverage["files"]["src/fieldtrue/fixture.py"]
    file_observation["missing_branches"].append([1, 2])
    with pytest.raises(HandoffError, match="branch observations overlap"):
        handoff_module._recompute_coverage(canonical_json_pretty(coverage))

    coverage = document()
    coverage["totals"] = None
    with pytest.raises(HandoffError, match="totals summary is invalid"):
        handoff_module._recompute_coverage(canonical_json_pretty(coverage))

    coverage = document()
    coverage["totals"]["covered_lines"] = True
    with pytest.raises(HandoffError, match="covered_lines is invalid"):
        handoff_module._recompute_coverage(canonical_json_pretty(coverage))

    coverage = document()
    coverage["totals"]["percent_covered"] = "90"
    with pytest.raises(HandoffError, match="percent_covered is invalid"):
        handoff_module._recompute_coverage(canonical_json_pretty(coverage))

    coverage = document()
    coverage["totals"]["percent_covered"] = 91.0
    with pytest.raises(HandoffError, match="percentage does not follow"):
        handoff_module._recompute_coverage(canonical_json_pretty(coverage))


def test_source_verdict_contract_preserves_legacy_and_freezes_current_limits(
    memory_records: tuple[ResearchMemoryRecord, ...],
) -> None:
    legacy = next(
        record
        for record in memory_records
        if record.event_id == handoff_module._SOURCE_VERDICT_EVENT_ID
    )
    assert isinstance(
        handoff_module._parse_source_payload(legacy.payload),
        handoff_module._LegacySourceVerdictPayload,
    )
    current = {
        **legacy.payload,
        "compute_consequence": handoff_module._CURRENT_SOURCE_COMPUTE_CONSEQUENCE,
        "finding": handoff_module._CURRENT_SOURCE_FINDING,
        "product_wedge": handoff_module._CURRENT_SOURCE_PRODUCT_WEDGE,
        "reconnaissance_scope": handoff_module._CURRENT_SOURCE_RECONNAISSANCE_SCOPE,
        "external_evidence_status": handoff_module._CURRENT_SOURCE_EXTERNAL_EVIDENCE_STATUS,
        "admissibility_boundary": handoff_module._CURRENT_SOURCE_ADMISSIBILITY_BOUNDARY,
        "source_architecture": list(handoff_module._CURRENT_SOURCE_ARCHITECTURE),
    }
    assert isinstance(
        handoff_module._parse_source_payload(current),
        handoff_module._CurrentSourceVerdictPayload,
    )
    for field, substitution in (
        ("reconnaissance_scope", "systematic"),
        ("external_evidence_status", "independently_verified"),
        ("admissibility_boundary", "All existing evidence is admitted."),
        ("compute_consequence", "GPU training is now authorized."),
        ("product_wedge", "Live flight command product."),
        ("source_architecture", ["one unsafe plane"]),
    ):
        with pytest.raises(HandoffError, match="payload violates its exact contract"):
            handoff_module._parse_source_payload({**current, field: substitution})


def test_versioned_recovery_text_is_exactly_frozen() -> None:
    assert handoff_module.RECOVERY_CHECKPOINT_ACTION == (
        "Hardened the deterministic Inbar recovery contract and verified its internal consistency."
    )
    assert handoff_module.RECOVERY_CHECKPOINT_OUTCOME == (
        "Recovery inputs and the blocked mission state are reproducibly bound to committed "
        "evidence."
    )
    assert handoff_module.RECOVERY_CHECKPOINT_AUTHORITY_EFFECT == (
        "No authority was granted; iter001-acquisition-contract remains blocked."
    )
    assert handoff_module.RECOVERY_HANDOFF_STATE == (
        "Inbar remains in bootstrap with iter001-acquisition-contract blocked and no mission "
        "authority active."
    )
    assert handoff_module.RECOVERY_HANDOFF_NEXT_ACTION == (
        "Complete and prospectively seal iter001-acquisition-contract before exercising any denied "
        "authority."
    )


def test_render_is_deterministic_clone_independent_and_self_reference_free(
    handoff_repo: Path,
    tmp_path: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    stale = handoff_repo / "HANDOFF.md"
    stale.write_text("UNIQUE_EXISTING_HANDOFF_SENTINEL\n", encoding="utf-8")

    first = render_handoff(handoff_repo)
    second = render_handoff(handoff_repo)

    clone = tmp_path / "different" / "clone-path"
    clone.parent.mkdir(parents=True)
    shutil.copytree(handoff_repo, clone)
    (clone / "README.md").chmod(0o600)
    (clone / "docs").chmod(0o700)
    cloned = render_handoff(clone)

    assert first == second == cloned
    assert b"UNIQUE_EXISTING_HANDOFF_SENTINEL" not in first
    assert handoff_repo.as_posix().encode() not in first
    assert clone.as_posix().encode() not in first
    assert b"Generated at" not in first
    assert b"Generated from commit" not in first
    assert re.search(rb"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}", first) is None
    assert b"- Branch:" not in first
    assert b"Git remotes" not in first
    assert b"github.com" not in first
    assert re.search(rb"\bHEAD\b", first) is None


def test_authority_closure_is_independent_of_prior_import_order() -> None:
    import_orders = (
        "",
        "import fieldtrue.cli\n",
        "import fieldtrue.experiment\nimport fieldtrue.cli\n",
        (
            "import fieldtrue.control_producer\n"
            "import fieldtrue.terminal_authority\n"
            "import fieldtrue.cli\n"
        ),
        (
            "import fieldtrue.cli\n"
            "import fieldtrue.terminal_authority\n"
            "import fieldtrue.control_producer\n"
        ),
        "import fieldtrue.shortcut_v2_ontology\n",
        (
            "import fieldtrue.adapters.local_replay\n"
            "import fieldtrue.cli\n"
            "import fieldtrue.control_launcher\n"
            "import fieldtrue.control_producer\n"
            "import fieldtrue.diagnosis\n"
            "import fieldtrue.experiment\n"
            "import fieldtrue.ports\n"
        ),
    )
    expected = [
        {
            "name": item.name,
            "path": item.repository_path,
            "sha256": handoff_module.sha256_bytes(item.imported_bytes),
        }
        for item in handoff_module._BOUND_FIELDTRUE_MODULES
    ]
    for prior_imports in import_orders:
        script = (
            prior_imports
            + "import json\n"
            + "import fieldtrue.handoff as handoff\n"
            + "from fieldtrue.canonical import sha256_bytes\n"
            + "print(json.dumps({'closure': ["
            + "{'name': item.name, 'path': item.repository_path, "
            + "'sha256': sha256_bytes(item.imported_bytes)} "
            + "for item in handoff._BOUND_FIELDTRUE_MODULES]}, "
            + "sort_keys=True))\n"
        )
        result = subprocess.run(  # noqa: S603 - current interpreter and fixed test program
            [sys.executable, "-c", script],
            cwd=_project_root(),
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        observed = json.loads(result.stdout)
        assert observed["closure"] == expected


def test_authority_closure_matches_the_fixed_reviewed_contract() -> None:
    assert tuple(item.name for item in handoff_module._BOUND_FIELDTRUE_MODULES) == (
        "fieldtrue",
        "fieldtrue.acquisition",
        "fieldtrue.active_selection",
        "fieldtrue.adapters",
        "fieldtrue.adapters.adapt",
        "fieldtrue.approvals",
        "fieldtrue.canonical",
        "fieldtrue.causal_laboratory",
        "fieldtrue.census",
        "fieldtrue.census_execution",
        "fieldtrue.control_authority",
        "fieldtrue.control_observation",
        "fieldtrue.control_protocol",
        "fieldtrue.domain",
        "fieldtrue.git_trust",
        "fieldtrue.graded_laboratory",
        "fieldtrue.handoff",
        "fieldtrue.masking",
        "fieldtrue.memory",
        "fieldtrue.method_campaign",
        "fieldtrue.mission",
        "fieldtrue.planning",
        "fieldtrue.readiness",
        "fieldtrue.receipts",
        "fieldtrue.runner_trust",
        "fieldtrue.runtime",
        "fieldtrue.schemas",
        "fieldtrue.shortcut_contracts",
        "fieldtrue.shortcut_v2_crossfit",
        "fieldtrue.shortcut_v2_hashing",
        "fieldtrue.shortcut_v2_ontology",
        "fieldtrue.shortcut_v2_release",
        "fieldtrue.shortcut_v2_target",
        "fieldtrue.shortcut_v2_tree",
        "fieldtrue.splits",
        "fieldtrue.terminal_authority",
        "fieldtrue.verification",
    )


def test_preloaded_wrapper_allowlist_matches_the_fixed_reviewed_contract() -> None:
    assert (
        frozenset(
            {
                "fieldtrue.adapters.local_replay",
                "fieldtrue.cli",
                "fieldtrue.control_launcher",
                "fieldtrue.control_producer",
                "fieldtrue.diagnosis",
                "fieldtrue.experiment",
                "fieldtrue.memory_cycle",
                "fieldtrue.ports",
                "fieldtrue.susceptibility_replay",
                "fieldtrue.shortcut_v2_terminal",
                "fieldtrue.validation_producer",
            }
        )
        == handoff_module._HANDOFF_ALLOWED_PRELOADED_MODULE_NAMES
    )


def test_snapshot_worker_rejects_source_changed_after_authority_preload(
    committed_worker_repo: Path,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "fresh-source-worker"
    clone_environment = handoff_module.git_environment()
    clone_environment["GIT_ALLOW_PROTOCOL"] = "file"
    subprocess.run(  # noqa: S603 - fixed trusted Git and local test paths
        [
            str(handoff_module.TRUSTED_GIT_PATH),
            "clone",
            "--quiet",
            "--no-hardlinks",
            "--",
            str(committed_worker_repo),
            str(repo),
        ],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        env=clone_environment,
        timeout=60,
    )
    _git(repo, "config", "user.name", "Inbar Handoff Test")
    _git(repo, "config", "user.email", "handoff@example.invalid")
    script = r"""
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve(strict=True)
sys.path.insert(0, str(root / "src"))
import fieldtrue.mission as stale_mission
from fieldtrue.git_trust import TRUSTED_GIT_PATH, git_environment

source_path = root / "src" / "fieldtrue" / "mission.py"
source_path.write_bytes(
    source_path.read_bytes()
    + b'\n\ndef validate_mission(repo_root):\n'
    + b'    from fieldtrue.handoff import HandoffError\n'
    + b'    raise HandoffError("fresh-source-executed-sentinel")\n'
)
subprocess.run(
    [str(TRUSTED_GIT_PATH), "add", "src/fieldtrue/mission.py"],
    cwd=root,
    check=True,
    env=git_environment(),
)
subprocess.run(
    [str(TRUSTED_GIT_PATH), "commit", "--quiet", "-m", "install fresh source sentinel"],
    cwd=root,
    check=True,
    env=git_environment(),
)
import fieldtrue.handoff as handoff
assert stale_mission.validate_mission.__code__.co_filename == str(source_path)
try:
    handoff.render_handoff(root)
except handoff.HandoffError as error:
    if str(error) != "fresh-source-executed-sentinel":
        raise
    print("FRESH_SOURCE_EXECUTED")
else:
    raise AssertionError("stale preloaded authority execution was accepted")
""".strip()
    result = subprocess.run(  # noqa: S603 - current interpreter and fixed adversarial program
        [sys.executable, "-c", script, str(repo)],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert result.stdout == "FRESH_SOURCE_EXECUTED\n"
    assert result.stderr == ""


def test_snapshot_worker_isolated_from_parent_authority_monkeypatch(
    committed_worker_repo: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "isolated-worker-source"
    clone_environment = handoff_module.git_environment()
    clone_environment["GIT_ALLOW_PROTOCOL"] = "file"
    subprocess.run(  # noqa: S603 - fixed trusted Git and local test paths
        [
            str(handoff_module.TRUSTED_GIT_PATH),
            "clone",
            "--quiet",
            "--no-hardlinks",
            "--",
            str(committed_worker_repo),
            str(repo),
        ],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        env=clone_environment,
        timeout=60,
    )
    _git(repo, "config", "user.name", "Inbar Handoff Test")
    _git(repo, "config", "user.email", "handoff@example.invalid")
    renderer = repo / handoff_module._RENDERER_PATH
    sentinel = b"# isolated committed worker source\n"
    # Keep this isolation test focused on the real snapshot/child boundary. Separate tests execute
    # the complete renderer and reject stale preloaded source.
    renderer.write_bytes(
        renderer.read_bytes()
        + b"\n\ndef _render_in_process(_repo_root):\n"
        + b'    return b"# isolated committed worker source\\n"\n'
    )
    _git(repo, "add", handoff_module._RENDERER_PATH)
    _git(repo, "commit", "--quiet", "-m", "install isolated worker sentinel")

    def reject_parent_execution(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("parent authority function executed")

    monkeypatch.setattr(handoff_module, "_render", reject_parent_execution)
    monkeypatch.setattr(handoff_module, "validate_mission", reject_parent_execution)

    document = render_handoff(repo)

    assert document == sentinel


def test_snapshot_worker_envelope_round_trip_and_error() -> None:
    document = b"# deterministic handoff\n"

    assert (
        handoff_module._decode_worker_output(handoff_module._worker_envelope(document)) == document
    )
    with pytest.raises(HandoffError, match="deliberate worker rejection"):
        handoff_module._decode_worker_output(
            handoff_module._worker_error_envelope(HandoffError("deliberate worker rejection"))
        )


@pytest.mark.parametrize(
    ("output", "message"),
    [
        (b"", "invalid envelope"),
        (b"{}", "invalid envelope"),
        (b"not-json\n", "invalid envelope"),
        (b'{"contract":"x","contract":"y"}\n', "invalid envelope"),
        (b'{"contract":"wrong","status":"ok"}\n', "invalid envelope"),
        (
            (b'{"contract":"inbar.handoff-snapshot-worker.v1","error":"","status":"error"}\n'),
            "invalid error",
        ),
        (
            (
                b'{"contract":"inbar.handoff-snapshot-worker.v1",'
                b'"document_base64":3,"document_sha256":"x",'
                b'"document_size":true,"status":"ok"}\n'
            ),
            "invalid document contract",
        ),
        (
            (
                b'{"contract":"inbar.handoff-snapshot-worker.v1",'
                b'"document_base64":"!","document_sha256":"x",'
                b'"document_size":1,"status":"ok"}\n'
            ),
            "invalid document bytes",
        ),
        (
            (
                b'{"contract":"inbar.handoff-snapshot-worker.v1",'
                b'"document_base64":"YQ==","document_sha256":"'
                + b"0" * 64
                + b'","document_size":1,"status":"ok"}\n'
            ),
            "document integrity failed",
        ),
    ],
)
def test_snapshot_worker_envelope_rejects_malformed_output(
    output: bytes,
    message: str,
) -> None:
    with pytest.raises(HandoffError, match=message):
        handoff_module._decode_worker_output(output)


def test_launch_snapshot_worker_decodes_framed_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    def completed(command: list[str], **kwargs: object) -> SimpleNamespace:
        observed["command"] = command
        observed["environment"] = kwargs["env"]
        return SimpleNamespace(
            returncode=0,
            stderr=b"",
            stdout=handoff_module._worker_envelope(b"worker document"),
        )

    monkeypatch.setattr(handoff_module.subprocess, "run", completed)

    assert handoff_module._launch_snapshot_worker(tmp_path) == b"worker document"
    command = observed["command"]
    assert isinstance(command, list)
    assert command[1:4] == ["-P", "-s", "-B"]
    environment = observed["environment"]
    assert isinstance(environment, dict)
    assert environment["HOME"] == handoff_module.os.environ["HOME"]
    assert environment["PATH"] == handoff_module.os.environ["PATH"]
    assert environment["PYTHONHASHSEED"] == "0"
    assert environment["PYTHONNOUSERSITE"] == "1"


@pytest.mark.parametrize("failure", ["timeout", "os-error", "nonzero", "stderr"])
def test_launch_snapshot_worker_fails_closed(
    failure: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def failed(*_args: object, **_kwargs: object) -> SimpleNamespace:
        if failure == "timeout":
            raise subprocess.TimeoutExpired("worker", 1)
        if failure == "os-error":
            raise OSError("worker unavailable")
        return SimpleNamespace(
            returncode=1 if failure == "nonzero" else 0,
            stderr=b"unexpected" if failure == "stderr" else b"",
            stdout=b"",
        )

    monkeypatch.setattr(handoff_module.subprocess, "run", failed)

    with pytest.raises(HandoffError, match=r"timed out|could not start|worker failed"):
        handoff_module._launch_snapshot_worker(tmp_path)


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        ("final-git", "Git state changed"),
        ("final-head", "Git state changed"),
        ("final-manifest", "source manifest changed"),
        ("final-memory", "research memory changed"),
        ("worker-handoff", "deliberate worker error"),
        ("worker-generic", "snapshot-bound handoff rendering failed"),
        ("worker-none", "worker returned no result"),
    ],
)
def test_snapshot_render_boundary_fails_closed_on_races_and_worker_failures(
    failure: str,
    message: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    manifest = handoff_module._RecoveryManifest((), (), 0, 0)
    changed_manifest = handoff_module._RecoveryManifest((), (), 0, 1)
    trust_calls = 0
    head_calls = 0
    manifest_calls = 0
    memory_calls = 0

    def trusted(*_args: object, **_kwargs: object) -> str:
        nonlocal trust_calls
        trust_calls += 1
        return "/different/git" if failure == "final-git" and trust_calls == 2 else "/usr/bin/git"

    def head(*_args: object, **_kwargs: object) -> str:
        nonlocal head_calls
        head_calls += 1
        return "1" * 40 if failure == "final-head" and head_calls == 2 else "0" * 40

    def recovery(*_args: object, **_kwargs: object) -> object:
        nonlocal manifest_calls
        manifest_calls += 1
        if failure == "final-manifest" and manifest_calls == 2:
            return changed_manifest
        return manifest

    def memory(*_args: object, **_kwargs: object) -> tuple[bytes, tuple[int, ...]]:
        nonlocal memory_calls
        memory_calls += 1
        if failure == "final-memory" and memory_calls == 2:
            return b"changed", (2,)
        return b"memory", (1,)

    def launch(_snapshot: Path) -> bytes | None:
        if failure == "worker-handoff":
            raise HandoffError("deliberate worker error")
        if failure == "worker-generic":
            raise RuntimeError("deliberate generic error")
        return None if failure == "worker-none" else b"document"

    monkeypatch.setattr(handoff_module, "trusted_repository_git", trusted)
    monkeypatch.setattr(handoff_module, "_git_head", head)
    monkeypatch.setattr(handoff_module, "_recovery_manifest", recovery)
    monkeypatch.setattr(handoff_module, "_read_regular_file_snapshot", memory)
    monkeypatch.setattr(handoff_module, "_v2_evidence_commit_from_memory", lambda _data: None)
    monkeypatch.setattr(handoff_module, "_materialize_repository_snapshot", lambda *_a, **_k: None)
    monkeypatch.setattr(handoff_module, "_launch_snapshot_worker", launch)

    with pytest.raises(HandoffError, match=message):
        handoff_module._render_snapshot_bound(root)


def test_snapshot_render_boundary_returns_only_worker_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    manifest = handoff_module._RecoveryManifest((), (), 0, 0)
    monkeypatch.setattr(
        handoff_module,
        "trusted_repository_git",
        lambda *_args, **_kwargs: "/usr/bin/git",
    )
    monkeypatch.setattr(handoff_module, "_git_head", lambda *_args, **_kwargs: "0" * 40)
    monkeypatch.setattr(handoff_module, "_recovery_manifest", lambda *_args: manifest)
    monkeypatch.setattr(
        handoff_module,
        "_read_regular_file_snapshot",
        lambda *_args: (b"memory", (1,)),
    )
    monkeypatch.setattr(handoff_module, "_v2_evidence_commit_from_memory", lambda _data: None)
    monkeypatch.setattr(handoff_module, "_materialize_repository_snapshot", lambda *_a, **_k: None)
    monkeypatch.setattr(handoff_module, "_launch_snapshot_worker", lambda _root: b"document")

    assert handoff_module._render_snapshot_bound(root) == b"document"


def test_render_rejects_unreviewed_preloaded_fieldtrue_module(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    monkeypatch.setitem(
        sys.modules,
        "fieldtrue.ambient_non_authority_fixture",
        ModuleType("fieldtrue.ambient_non_authority_fixture"),
    )

    with pytest.raises(HandoffError, match="unreviewed preloaded Fieldtrue modules"):
        render_handoff(handoff_repo)


def test_render_rejects_unbound_preloaded_wrapper_source(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    monkeypatch.setitem(sys.modules, "fieldtrue.cli", ModuleType("fieldtrue.cli"))

    with pytest.raises(HandoffError, match="preloaded Fieldtrue wrapper source cannot be bound"):
        render_handoff(handoff_repo)


def test_render_includes_current_memory_checkpoint_and_public_substrate_finding(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    checkpoint, handoff = _selected_recovery_records(memory_records)

    document = render_handoff(handoff_repo).decode("utf-8")

    assert "`KILL_PUBLIC_SUBSTRATE`" in document
    source_record = next(
        item for item in memory_records if item.event_id == "iter001-public-substrate-verdict-v1"
    )
    assert f"Source verdict event: `{source_record.event_id}`" in document
    assert f"Source verdict event hash: `{source_record.event_hash}`" in document
    assert f"Source verdict summary: {source_record.summary}" in document
    assert (
        "Source architecture: physical admission, causal laboratory, independent reality"
        in document
    )
    assert "Compute consequence: GPU training remains blocked." in document
    assert handoff.event_id in document
    assert checkpoint.event_id in document
    assert checkpoint.payload["implementation_commit"] in document
    validation = checkpoint.payload["validation"]
    assert f"{validation['tests_passed']} passed, {validation['tests_skipped']} skipped" in document
    assert f"{validation['branch_coverage_percent']:.2f} percent" in document
    assert f"Research-memory events: {len(memory_records)}" in document
    assert memory_records[-1].event_hash in document
    assert "Canonical control authority: `bootstrap`" in document
    assert "Publication transition: `blocked`" in document


def test_source_digest_is_deterministic_and_binds_unrendered_source_bytes(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    before = render_handoff(handoff_repo)
    contract_path = handoff_repo / "mission" / "contract.json"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    contract["source_digest_fixture"] = "two"
    contract_path.write_text(
        json.dumps(contract, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    after = render_handoff(handoff_repo)

    assert _input_digest(before) != _input_digest(after)
    assert before.replace(_input_digest(before).encode(), b"DIGEST") == after.replace(
        _input_digest(after).encode(), b"DIGEST"
    )


def test_recovery_digest_binds_claims_outside_the_rendered_fields(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    before = render_handoff(handoff_repo)
    claim_path = handoff_repo / "claims" / "registry.jsonl"
    claim_path.write_bytes(claim_path.read_bytes() + b'{"claim":"still-blocked"}\n')

    after = render_handoff(handoff_repo)

    assert _input_digest(before) != _input_digest(after)
    assert before.replace(_input_digest(before).encode(), b"DIGEST") == after.replace(
        _input_digest(after).encode(), b"DIGEST"
    )


def test_recovery_digest_ignores_empty_directories_but_binds_files_within_them(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    before_manifest = handoff_module._recovery_manifest(handoff_repo)
    before = render_handoff(handoff_repo)
    cache_path = (
        handoff_repo
        / "nonexistent"
        / "Library"
        / "Caches"
        / "com.apple.python"
        / "Library"
        / "Developer"
        / "CommandLineTools"
        / "Library"
        / "Frameworks"
        / "Python3.framework"
        / "Versions"
        / "3.9"
        / "lib"
        / "python3.9"
        / "encodings"
    )
    cache_path.mkdir(parents=True)

    empty_manifest = handoff_module._recovery_manifest(handoff_repo)
    with_empty_directories = render_handoff(handoff_repo)

    assert before_manifest.files == empty_manifest.files
    assert before_manifest.directories != empty_manifest.directories
    assert before == with_empty_directories

    (cache_path / "artifact.pyc").write_bytes(b"content-bearing input\n")
    with_file = render_handoff(handoff_repo)

    assert _input_digest(with_file) != _input_digest(before)
    assert with_file.replace(_input_digest(with_file).encode(), b"DIGEST") == before.replace(
        _input_digest(before).encode(), b"DIGEST"
    )


def test_render_binds_the_imported_renderer_source_to_repository_source(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    (handoff_repo / "src" / "fieldtrue" / "handoff.py").write_text("VALUE = 1\n", encoding="utf-8")

    with pytest.raises(HandoffError, match="imported handoff renderer source differs"):
        render_handoff(handoff_repo)


def test_render_rejects_imported_renderer_code_that_differs_from_source(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    module_path = Path(handoff_module.__file__).resolve(strict=True)
    monkeypatch.setattr(
        handoff_module,
        "_IMPORTED_MODULE_CODE",
        compile("VALUE = 1\n", str(module_path), "exec"),
    )

    with pytest.raises(HandoffError, match="executing handoff renderer code differs"):
        render_handoff(handoff_repo)


def test_render_rejects_bound_dependency_source_mismatch(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    dependency = next(
        item for item in handoff_module._BOUND_FIELDTRUE_MODULES if item.name == "fieldtrue.memory"
    )
    dependency_path = handoff_repo / dependency.repository_path
    dependency_path.write_bytes(dependency_path.read_bytes() + b"# changed dependency\n")

    with pytest.raises(HandoffError, match=r"imported Fieldtrue module source differs.*memory"):
        render_handoff(handoff_repo)


def test_render_rejects_bound_dependency_loader_code_mismatch(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    changed_bindings = tuple(
        binding._replace(loader_code=compile("VALUE = 1\n", binding.imported_path, "exec"))
        if binding.name == "fieldtrue.memory"
        else binding
        for binding in handoff_module._BOUND_FIELDTRUE_MODULES
    )
    monkeypatch.setattr(handoff_module, "_BOUND_FIELDTRUE_MODULES", changed_bindings)

    with pytest.raises(HandoffError, match=r"loader code differs.*memory"):
        render_handoff(handoff_repo)


def test_render_rejects_new_unbound_fieldtrue_module(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)

    def validation(_repo: Path) -> MissionValidation:
        monkeypatch.setitem(
            sys.modules,
            "fieldtrue.unbound_handoff_fixture",
            ModuleType("fieldtrue.unbound_handoff_fixture"),
        )
        return _mission_report()

    monkeypatch.setattr(handoff_module, "validate_mission", validation)

    with pytest.raises(HandoffError, match="unbound Fieldtrue modules loaded"):
        render_handoff(handoff_repo)


def test_render_rejects_unbound_fieldtrue_import_through_meta_path(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)

    class VirtualLoader:
        def create_module(self, spec: object) -> None:
            del spec
            return None

        def exec_module(self, module: ModuleType) -> None:
            del module

    class VirtualFinder:
        def find_spec(
            self,
            fullname: str,
            path: object,
            target: object = None,
        ) -> object:
            del path, target
            if fullname == "fieldtrue.unbound_import_fixture":
                return importlib.util.spec_from_loader(fullname, VirtualLoader())
            return None

    monkeypatch.setattr(sys, "meta_path", [*sys.meta_path, VirtualFinder()])

    def validation(_repo: Path) -> MissionValidation:
        importlib.import_module("fieldtrue.unbound_import_fixture")
        return _mission_report()

    monkeypatch.setattr(handoff_module, "validate_mission", validation)

    with pytest.raises(HandoffError, match="unbound Fieldtrue module import during handoff"):
        render_handoff(handoff_repo)


def test_write_and_check_round_trip_and_detect_stale_document(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)

    path = write_handoff(handoff_repo)

    assert path == handoff_repo / "HANDOFF.md"
    assert path.read_bytes() == render_handoff(handoff_repo)
    check_handoff(handoff_repo)
    path.write_bytes(path.read_bytes() + b"manual edit\n")
    with pytest.raises(HandoffError, match=r"HANDOFF\.md is stale"):
        check_handoff(handoff_repo)


def test_check_rejects_missing_and_symbolic_link_handoff(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    with pytest.raises(HandoffError, match=r"HANDOFF\.md is unavailable"):
        check_handoff(handoff_repo)
    target = handoff_repo / "target.md"
    target.write_text("not authoritative\n", encoding="utf-8")
    (handoff_repo / "HANDOFF.md").symlink_to(target)
    with pytest.raises(HandoffError, match=r"HANDOFF\.md is unavailable"):
        check_handoff(handoff_repo)


def test_render_rejects_symbolic_link_parent_component(
    handoff_repo: Path,
    tmp_path: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    outside = tmp_path / "outside-mission"
    (handoff_repo / "mission").replace(outside)
    (handoff_repo / "mission").symlink_to(outside, target_is_directory=True)

    with pytest.raises(HandoffError, match="traverses a symbolic link"):
        render_handoff(handoff_repo)


def test_check_rejects_handoff_change_during_render(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    write_handoff(handoff_repo)
    original_read = handoff_module._read_regular_file
    handoff_reads = 0

    def changing_read(repo_root: Path, relative: str, label: str) -> bytes:
        nonlocal handoff_reads
        data = original_read(repo_root, relative, label)
        if relative == "HANDOFF.md":
            handoff_reads += 1
            if handoff_reads == 2:
                return data + b"concurrent edit\n"
        return data

    monkeypatch.setattr(handoff_module, "_read_regular_file", changing_read)

    with pytest.raises(HandoffError, match=r"HANDOFF\.md is stale"):
        check_handoff(handoff_repo)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("missing", "does not link a checkpoint"),
        ("unknown", "checkpoint link is not an earlier event"),
        ("future", "checkpoint link is not an earlier event"),
        ("blocked", "must link a passing execution checkpoint"),
    ],
)
def test_render_rejects_missing_or_invalid_checkpoint_links(
    mutation: str,
    message: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint, handoff = _selected_recovery_records(memory_records)
    if mutation == "missing":
        records = _replace_record(memory_records, handoff.event_id, links={})
    elif mutation == "unknown":
        records = _replace_record(memory_records, handoff.event_id, links={"checkpoint": "absent"})
    elif mutation == "future":
        records = _replace_record(
            memory_records,
            checkpoint.event_id,
            sequence=memory_records[-1].sequence + 1,
        )
    else:
        records = _replace_record(memory_records, checkpoint.event_id, status=MemoryStatus.BLOCKED)
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(HandoffError, match=message):
        render_handoff(handoff_repo)


@pytest.mark.parametrize(
    ("target", "payload_update", "message"),
    [
        (
            "handoff",
            {"remaining_gates": []},
            "payload violates",
        ),
        (
            "source",
            {"product_wedge": "line one\nline two"},
            "must be one trimmed line",
        ),
        (
            "checkpoint",
            {"unexpected": "not admitted"},
            "payload violates",
        ),
        (
            "source",
            {"finding": "PASS_PUBLIC_SUBSTRATE"},
            "payload violates",
        ),
    ],
)
def test_render_rejects_malformed_display_payloads(
    target: str,
    payload_update: dict[str, object],
    message: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint, handoff = _selected_recovery_records(memory_records)
    event_id = {
        "checkpoint": checkpoint.event_id,
        "handoff": handoff.event_id,
        "source": "iter001-public-substrate-verdict-v1",
    }[target]
    record = next(item for item in memory_records if item.event_id == event_id)
    payload = {**record.payload, **payload_update}
    records = _replace_record(memory_records, event_id, payload=payload)
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(HandoffError, match=message):
        render_handoff(handoff_repo)


def test_render_rejects_coerced_checkpoint_metrics(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint, _handoff = _selected_recovery_records(memory_records)
    validation = {**checkpoint.payload["validation"], "tests_passed": "513"}
    payload = {**checkpoint.payload, "validation": validation}
    records = _replace_record(memory_records, checkpoint.event_id, payload=payload)
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(HandoffError, match="payload violates its exact contract"):
        render_handoff(handoff_repo)


def test_render_rejects_a_corrected_selected_event(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint, handoff = _versioned_recovery_records(memory_records)
    correction = memory_records[59].model_copy(
        update={
            "sequence": checkpoint.sequence + 1,
            "event_id": "fixture-handoff-correction",
            "corrects_event_id": checkpoint.event_id,
        }
    )
    handoff = handoff.model_copy(update={"sequence": correction.sequence + 1})
    records = (*memory_records, checkpoint, correction, handoff)
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(HandoffError, match="selected recovery events were corrected"):
        render_handoff(handoff_repo)


def test_render_rejects_an_unversioned_newer_handoff(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _checkpoint, prior = _selected_recovery_records(memory_records)
    payload = {**prior.payload, "handoff_contract": None}
    newest = prior.model_copy(
        update={
            "sequence": memory_records[-1].sequence + 1,
            "event_id": "fixture-newest-valid-handoff",
            "payload": payload,
        }
    )
    records = (*memory_records, newest)
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(HandoffError, match="lacks the versioned handoff contract"):
        render_handoff(handoff_repo)


def test_render_selects_a_versioned_commit_bound_newer_handoff(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint, newest = _versioned_recovery_records(memory_records)
    _install_verified_dependencies(monkeypatch, (*memory_records, checkpoint, newest))

    document = render_handoff(handoff_repo).decode("utf-8")

    assert "Active handoff: `fixture-versioned-handoff`" in document
    assert f"State: {handoff_module.RECOVERY_HANDOFF_STATE}" in document
    assert "This explicit list is non-exhaustive." in document
    assert "`iter001-acquisition-contract` remains blocked." in document
    assert "This handoff grants no authority." in document

    substituted = newest.model_copy(
        update={
            "links": {
                **newest.links,
                "engine_boundary": "iter001-public-substrate-verdict-v1",
            }
        }
    )
    _install_verified_dependencies(monkeypatch, (*memory_records, checkpoint, substituted))
    with pytest.raises(HandoffError, match="lacks the versioned handoff contract"):
        render_handoff(handoff_repo)

    later = memory_records[59].model_copy(
        update={
            "sequence": newest.sequence + 1,
            "event_id": "fixture-later-state-event",
        }
    )
    _install_verified_dependencies(monkeypatch, (*memory_records, checkpoint, newest, later))
    with pytest.raises(HandoffError, match="must be the final research-memory event"):
        render_handoff(handoff_repo)


@pytest.mark.parametrize(
    ("target", "field"),
    [
        ("checkpoint", "action"),
        ("checkpoint", "outcome"),
        ("checkpoint", "authority_effect"),
        ("handoff", "state"),
        ("handoff", "next_action"),
    ],
)
def test_versioned_recovery_rejects_contradictory_canonical_text(
    target: str,
    field: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint, handoff = _versioned_recovery_records(memory_records)
    selected = checkpoint if target == "checkpoint" else handoff
    changed = selected.model_copy(
        update={"payload": {**selected.payload, field: "Authority is now active."}}
    )
    if target == "checkpoint":
        checkpoint = changed
        handoff = handoff.model_copy(
            update={"links": {**handoff.links, "checkpoint": changed.event_id}}
        )
    else:
        handoff = changed
    _install_verified_dependencies(monkeypatch, (*memory_records, checkpoint, handoff))

    with pytest.raises(HandoffError, match="lacks the versioned handoff contract"):
        render_handoff(handoff_repo)


@pytest.mark.parametrize(
    "report",
    [
        _mission_report(extra_failures=("unexpected-check",)),
        _mission_report(omit_expected=True),
    ],
)
def test_render_rejects_mission_blocker_drift(
    report: MissionValidation,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records, report=report)

    with pytest.raises(HandoffError, match="current mission blockers differ"):
        render_handoff(handoff_repo)


def test_render_rejects_expected_blocker_with_different_failure_cause(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _mission_report()
    checks = tuple(
        check.model_copy(update={"detail": "different acquisition defect"})
        if check.check_id == "iter001-acquisition-contract"
        else check
        for check in report.checks
    )
    _install_verified_dependencies(
        monkeypatch,
        memory_records,
        report=MissionValidation(passed=False, checks=checks),
    )

    with pytest.raises(HandoffError, match="unexpected failure cause"):
        render_handoff(handoff_repo)


def test_render_rejects_checkpoint_that_changes_bootstrap_blocker_policy(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint, _handoff = _selected_recovery_records(memory_records)
    validation = {**checkpoint.payload["validation"], "expected_blockers": ["different-blocker"]}
    payload = {**checkpoint.payload, "validation": validation}
    records = _replace_record(memory_records, checkpoint.event_id, payload=payload)
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(HandoffError, match="blocker policy differs"):
        render_handoff(handoff_repo)


def test_render_rejects_schema_drift(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(
        monkeypatch,
        memory_records,
        schema_errors=["stale schema: protocol/schemas/example.schema.json"],
    )

    with pytest.raises(HandoffError, match="committed schema is stale"):
        render_handoff(handoff_repo)


def test_render_rejects_schema_inventory_drift(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    (handoff_repo / "protocol" / "schemas" / "unexpected.schema.json").write_text(
        "{}\n",
        encoding="utf-8",
    )

    with pytest.raises(HandoffError, match="schema inventory differs"):
        render_handoff(handoff_repo)


def test_render_rejects_duplicate_source_object_keys(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    (handoff_repo / "mission" / "name.json").write_text(
        '{"canonical_slug":"inbar","canonical_slug":"inbar","status":"pending"}\n',
        encoding="utf-8",
    )

    with pytest.raises(HandoffError, match="duplicate object keys"):
        render_handoff(handoff_repo)


def test_render_rejects_nonfinite_source_json(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    (handoff_repo / "mission" / "name.json").write_text(
        '{"canonical_slug":"inbar","score":NaN,"status":"pending"}\n',
        encoding="utf-8",
    )

    with pytest.raises(HandoffError, match="nonfinite JSON"):
        render_handoff(handoff_repo)

    (handoff_repo / "mission" / "name.json").write_text(
        '{"canonical_slug":"inbar","score":1e999,"status":"pending"}\n',
        encoding="utf-8",
    )
    with pytest.raises(HandoffError, match="nonfinite JSON"):
        render_handoff(handoff_repo)


def test_render_escapes_memory_text_before_markdown_emission(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy_records = _legacy_recovery_memory(memory_records)
    handoff = next(
        record for record in legacy_records if record.event_id == _LEGACY_HANDOFF_EVENT_ID
    )
    records = _replace_record(
        legacy_records,
        handoff.event_id,
        payload={**handoff.payload, "next_action": "<!-- hide authority --> # forged"},
    )
    _install_verified_dependencies(monkeypatch, records)

    document = render_handoff(handoff_repo).decode("utf-8")

    assert "<!--" not in document
    assert "&lt;!-- hide authority --&gt; \\# forged" in document


@pytest.mark.parametrize("character", ["\u0085", "\u2028", "\u2029", "\u202e"])
def test_render_rejects_unicode_line_and_direction_controls(
    character: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy_records = _legacy_recovery_memory(memory_records)
    handoff = next(
        record for record in legacy_records if record.event_id == _LEGACY_HANDOFF_EVENT_ID
    )
    records = _replace_record(
        legacy_records,
        handoff.event_id,
        payload={**handoff.payload, "next_action": f"trusted{character}forged"},
    )
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(HandoffError, match="control character"):
        render_handoff(handoff_repo)


def test_render_rejects_unicode_controls_in_source_contracts(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    name_path = handoff_repo / "mission" / "name.json"
    value = json.loads(name_path.read_text(encoding="utf-8"))
    value["status"] = "pending\u202eapproved"
    name_path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(HandoffError, match="control character"):
        render_handoff(handoff_repo)


def test_handoff_snapshots_reject_hard_link_aliases(
    handoff_repo: Path,
    tmp_path: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    contract = handoff_repo / "mission" / "contract.json"
    (tmp_path / "contract-alias.json").hardlink_to(contract)

    with pytest.raises(HandoffError, match="must not be hard linked"):
        render_handoff(handoff_repo)


def test_check_rejects_a_hard_linked_handoff(
    handoff_repo: Path,
    tmp_path: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    path = write_handoff(handoff_repo)
    (tmp_path / "handoff-alias.md").hardlink_to(path)

    with pytest.raises(HandoffError, match="must not be hard linked"):
        check_handoff(handoff_repo)


def test_write_handoff_rejects_input_change_between_render_and_write(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    original_write = handoff_module.atomic_write

    def changing_write(path: Path, content: bytes) -> None:
        original_write(path, content)
        contract_path = handoff_repo / "mission" / "contract.json"
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        contract["source_digest_fixture"] = "changed-after-render"
        contract_path.write_text(
            json.dumps(contract, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    monkeypatch.setattr(handoff_module, "atomic_write", changing_write)

    with pytest.raises(HandoffError, match=r"HANDOFF\.md is stale"):
        write_handoff(handoff_repo)


@pytest.mark.parametrize("mode", ["aggregate", "duplicate", "substitution"])
def test_render_binds_the_complete_mission_report_contract(
    mode: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _mission_report()
    if mode == "aggregate":
        report = report.model_copy(update={"passed": True})
        message = "aggregate is internally inconsistent"
    else:
        checks = list(report.checks)
        replacement = checks[-2].model_copy(
            update={"check_id": checks[-1].check_id if mode == "duplicate" else "substituted-check"}
        )
        checks[-2] = replacement
        report = MissionValidation(passed=False, checks=tuple(checks))
        message = "duplicate check IDs" if mode == "duplicate" else "check inventory differs"
    _install_verified_dependencies(monkeypatch, memory_records, report=report)

    with pytest.raises(HandoffError, match=message):
        render_handoff(handoff_repo)


@pytest.mark.parametrize("target", ["checkpoint", "handoff"])
def test_render_requires_commit_bound_recovery_evidence(
    target: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint, handoff = _selected_recovery_records(memory_records)
    event_id = checkpoint.event_id if target == "checkpoint" else handoff.event_id
    records = _replace_record(memory_records, event_id, evidence=())
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(HandoffError, match="lacks required Git-anchored evidence roles"):
        render_handoff(handoff_repo)


@pytest.mark.parametrize(
    "changed_label",
    [
        "mission/contract.json",
        "memory/research_engine_extraction.jsonl",
        "schema alpha.schema.json",
    ],
)
def test_render_rejects_input_change_during_snapshot(
    changed_label: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    original_read = handoff_module._read_regular_file
    reads = 0

    def changing_read(repo_root: Path, relative: str, label: str) -> bytes:
        nonlocal reads
        data = original_read(repo_root, relative, label)
        if label == changed_label:
            reads += 1
            if reads == 2:
                return data[:-1] + bytes([data[-1] ^ 1])
        return data

    monkeypatch.setattr(handoff_module, "_read_regular_file", changing_read)

    with pytest.raises(HandoffError, match=r"changed during .*rendering"):
        render_handoff(handoff_repo)


def test_render_rejects_mission_state_change_during_rendering(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _mission_report()
    _install_verified_dependencies(monkeypatch, memory_records, report=report)
    changed_checks = tuple(
        check.model_copy(update={"detail": "changed during rendering"})
        if check.check_id == "owner-boundary"
        else check
        for check in report.checks
    )
    reports = iter(
        (
            report,
            MissionValidation(passed=False, checks=changed_checks),
        )
    )
    monkeypatch.setattr(handoff_module, "validate_mission", lambda _repo: next(reports))

    with pytest.raises(HandoffError, match="mission validation changed during handoff rendering"):
        render_handoff(handoff_repo)


def test_render_rechecks_source_after_unchanged_final_mission_validation(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _mission_report()
    _install_verified_dependencies(monkeypatch, memory_records, report=report)
    calls = 0

    def changing_validation(_repo: Path) -> MissionValidation:
        nonlocal calls
        calls += 1
        if calls == 2:
            contract_path = handoff_repo / "mission" / "contract.json"
            contract_path.write_bytes(contract_path.read_bytes() + b" ")
        return report

    monkeypatch.setattr(handoff_module, "validate_mission", changing_validation)

    with pytest.raises(
        HandoffError,
        match=r"handoff source changed during rendering: mission/contract\.json",
    ):
        render_handoff(handoff_repo)


def test_render_rejects_recovery_input_aba_change_with_restored_bytes(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _mission_report()
    _install_verified_dependencies(monkeypatch, memory_records, report=report)
    claim_path = handoff_repo / "claims" / "registry.jsonl"
    original = claim_path.read_bytes()
    calls = 0

    def changing_validation(_repo: Path) -> MissionValidation:
        nonlocal calls
        calls += 1
        if calls == 2:
            replacement = claim_path.with_suffix(".replacement")
            replacement.write_bytes(b'{"claim":"temporarily-active"}\n')
            replacement.replace(claim_path)
            claim_path.write_bytes(original)
        return report

    monkeypatch.setattr(handoff_module, "validate_mission", changing_validation)

    with pytest.raises(HandoffError, match="recovery input manifest changed"):
        render_handoff(handoff_repo)


@pytest.mark.parametrize("mode", ["checkpoint", "handoff"])
def test_render_rejects_duplicate_checkpoint_and_handoff_lists(
    mode: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint, handoff = _selected_recovery_records(memory_records)
    record = checkpoint if mode == "checkpoint" else handoff
    if mode == "checkpoint":
        validation = {
            **record.payload["validation"],
            "expected_blockers": [
                "iter001-acquisition-contract",
                "iter001-acquisition-contract",
            ],
        }
        payload_update: dict[str, object] = {"validation": validation}
    else:
        payload_update = {"remaining_gates": ["duplicate gate", "duplicate gate"]}
    records = _replace_record(
        memory_records,
        record.event_id,
        payload={**record.payload, **payload_update},
    )
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(HandoffError, match="payload violates its exact contract"):
        render_handoff(handoff_repo)


@pytest.mark.parametrize("mode", ["absent", "not-blocked"])
def test_render_requires_a_blocked_inbar_handoff(
    mode: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _checkpoint, handoff = _selected_recovery_records(memory_records)
    if mode == "absent":
        records = tuple(
            record
            for record in memory_records
            if record.event_type != handoff_module.MemoryEventType.HANDOFF
        )
    else:
        records = _replace_record(memory_records, handoff.event_id, status=MemoryStatus.PASS)
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(HandoffError, match=r"no Inbar handoff|preserve blocked"):
        render_handoff(handoff_repo)


@pytest.mark.parametrize("mode", ["invalid", "empty"])
def test_render_rejects_invalid_or_empty_memory_snapshot(
    mode: str,
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        handoff_module,
        "_render_snapshot_bound",
        handoff_module._render_in_process,
    )
    monkeypatch.setattr(handoff_module, "validate_mission", lambda _repo: _mission_report())
    if mode == "invalid":
        monkeypatch.setattr(
            handoff_module,
            "load_memory_records_bytes",
            lambda _data: (_ for _ in ()).throw(ValueError("invalid")),
        )
    else:
        monkeypatch.setattr(handoff_module, "load_memory_records_bytes", lambda _data: ())

    with pytest.raises(HandoffError, match=r"research memory is invalid|research memory is empty"):
        render_handoff(handoff_repo)


@pytest.mark.parametrize("target", ["source", "engine"])
def test_render_requires_frozen_source_and_engine_events(
    target: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id = (
        "iter001-public-substrate-verdict-v1"
        if target == "source"
        else "future-research-engine-shortcut-v2-lessons-v1"
    )
    records = tuple(record for record in memory_records if record.event_id != event_id)
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(HandoffError, match="required research-memory event is invalid"):
        render_handoff(handoff_repo)


@pytest.mark.parametrize("target", ["checkpoint", "handoff"])
def test_render_rejects_checkpoint_commit_substitution(
    target: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint, handoff = _selected_recovery_records(memory_records)
    event_id = checkpoint.event_id if target == "checkpoint" else handoff.event_id
    records = _replace_record(memory_records, event_id, source_commit="f" * 40)
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(HandoffError, match="source commit differs"):
        render_handoff(handoff_repo)


@pytest.mark.parametrize("mode", ["unexpected", "policy", "count"])
def test_render_rejects_checkpoint_validation_policy_drift(
    mode: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint, _handoff = _selected_recovery_records(memory_records)
    validation = dict(checkpoint.payload["validation"])
    if mode == "unexpected":
        validation["unexpected_blockers"] = ["unexpected-check"]
    elif mode == "policy":
        validation["expected_blockers"] = []
    else:
        validation["mission_checks"] = 23
    records = _replace_record(
        memory_records,
        checkpoint.event_id,
        payload={**checkpoint.payload, "validation": validation},
    )
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(
        HandoffError,
        match=r"unexpected mission blockers|blocker policy differs|check count differs",
    ):
        render_handoff(handoff_repo)


@pytest.mark.parametrize("mode", ["identity", "publication", "authority"])
def test_render_rejects_identity_and_authority_state_drift(
    mode: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    if mode == "identity":
        path = handoff_repo / "mission" / "name.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["canonical_slug"] = "fieldtrue"
    elif mode == "publication":
        path = handoff_repo / "mission" / "loop.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["publication_transition"] = {"status": "published"}
    else:
        path = handoff_repo / "protocol" / "acquisition" / "iter001_contract.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["control_authority_status"] = "sealed"
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(HandoffError, match=r"identity contracts disagree|cannot imply activated"):
        render_handoff(handoff_repo)


def test_render_rejects_schema_inventory_and_directory_race(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    extra = handoff_repo / "protocol" / "schemas" / "extra.schema.json"
    extra.write_text("{}\n", encoding="utf-8")
    with pytest.raises(HandoffError, match="schema inventory differs"):
        render_handoff(handoff_repo)
    extra.unlink()

    original_snapshot = handoff_module._directory_snapshot
    calls = 0

    def changed_snapshot(
        repo_root: Path, relative: str, label: str
    ) -> tuple[tuple[str, ...], tuple[int, ...]]:
        nonlocal calls
        snapshot = original_snapshot(repo_root, relative, label)
        calls += 1
        if calls == 2:
            return snapshot[0], (*snapshot[1][:-1], snapshot[1][-1] + 1)
        return snapshot

    monkeypatch.setattr(handoff_module, "_directory_snapshot", changed_snapshot)
    with pytest.raises(HandoffError, match="schema directory changed"):
        render_handoff(handoff_repo)


def test_low_level_handoff_snapshot_guards(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(HandoffError, match="unsafe repository path"):
        handoff_module._read_regular_file(handoff_repo, "../escape", "fixture")
    with pytest.raises(HandoffError, match="unsafe repository path"):
        handoff_module._directory_snapshot(handoff_repo, "/escape", "fixture")
    with pytest.raises(HandoffError, match="must be a regular file"):
        handoff_module._read_regular_file(handoff_repo, "mission", "fixture")
    monkeypatch.setattr(handoff_module, "_MAX_INPUT_BYTES", 4)
    with pytest.raises(HandoffError, match="exceeds the handoff input limit"):
        handoff_module._read_regular_file(
            handoff_repo,
            "mission/contract.json",
            "fixture",
        )


@pytest.mark.parametrize(
    ("limit_name", "message"),
    [
        ("_MAX_RECOVERY_INPUT_DIRECTORIES", "directory count exceeds"),
        ("_MAX_RECOVERY_INPUT_ENTRIES", "entry count exceeds"),
    ],
)
def test_recovery_manifest_bounds_directory_inventory(
    limit_name: str,
    message: str,
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(handoff_module, limit_name, 0)

    with pytest.raises(HandoffError, match=message):
        handoff_module._recovery_manifest(handoff_repo)


@pytest.mark.parametrize("payload", [b"[1,2,3]\n", b"not json\n"])
def test_render_rejects_nonobject_or_invalid_json_source(
    payload: bytes,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    (handoff_repo / "mission" / "name.json").write_bytes(payload)
    with pytest.raises(HandoffError, match=r"must be a JSON object|not valid UTF-8 JSON"):
        render_handoff(handoff_repo)


def test_render_wraps_unexpected_input_errors(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        handoff_module,
        "_render_snapshot_bound",
        handoff_module._render_in_process,
    )
    monkeypatch.setattr(
        handoff_module,
        "_render",
        lambda _repo: (_ for _ in ()).throw(OSError("fixture")),
    )
    with pytest.raises(HandoffError, match="inputs could not be verified"):
        render_handoff(handoff_repo)


def test_render_rejects_nonfinite_json_source_value(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    contract_path = handoff_repo / "mission" / "contract.json"
    contract_path.write_bytes(contract_path.read_bytes().replace(b'"one"', b"NaN"))

    with pytest.raises(HandoffError, match="contains nonfinite JSON value"):
        render_handoff(handoff_repo)


def test_import_guard_rejects_unbound_fieldtrue_module_directly() -> None:
    guard = handoff_module._RejectUnboundFieldtrueImports(
        handoff_module._HANDOFF_AUTHORITY_MODULE_NAME_SET
    )

    assert guard.find_spec("fieldtrue.handoff", None) is None
    with pytest.raises(HandoffError, match="unbound Fieldtrue module import"):
        guard.find_spec("fieldtrue.adversarial_fixture", None)


@pytest.mark.parametrize(
    ("mode", "message"),
    [
        ("not-module", "configured Fieldtrue authority module is not loaded"),
        ("no-loader", "has no source-code loader"),
        ("outside-root", "outside the source root"),
        ("not-source", "is not Python source"),
        ("no-code", "has no executable module code"),
    ],
)
def test_capture_bound_module_closure_rejects_malformed_population(
    mode: str,
    message: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    name = "fieldtrue.canonical"
    if mode == "not-module":
        monkeypatch.setitem(sys.modules, name, object())
    else:
        module = ModuleType(name)
        if mode == "no-loader":
            module.__file__ = str(Path(handoff_module.__file__).resolve(strict=True))
        else:
            source = tmp_path / "capture.py"
            source.write_text("VALUE = 1\n", encoding="utf-8")
            if mode in {"not-source", "no-code"}:
                source_root = Path(handoff_module.__file__).resolve(strict=True).parents[1]
                source = (
                    source_root / "fieldtrue" / "py.typed"
                    if mode == "not-source"
                    else source_root / "fieldtrue" / "__init__.py"
                )

            class Loader:
                def get_code(self, fullname: str) -> object:
                    del fullname
                    if mode == "no-code":
                        return None
                    return compile(source.read_text(encoding="utf-8"), str(source), "exec")

            module.__file__ = str(source)
            module.__spec__ = type("FixtureSpec", (), {"loader": Loader()})()
        monkeypatch.setitem(sys.modules, name, module)

    with pytest.raises(RuntimeError, match=message):
        handoff_module._capture_bound_fieldtrue_modules()


def test_capture_bound_module_closure_requires_authority_members(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "modules", {})
    with pytest.raises(RuntimeError, match="configured Fieldtrue authority module is not loaded"):
        handoff_module._capture_bound_fieldtrue_modules()


def test_capture_bound_module_closure_requires_verification_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delitem(sys.modules, "fieldtrue.verification")
    with pytest.raises(RuntimeError, match="configured Fieldtrue authority module is not loaded"):
        handoff_module._capture_bound_fieldtrue_modules()


@pytest.mark.parametrize("mode", ["unexpected-duplicate", "overlap", "mission-duplicate"])
def test_checkpoint_validation_rejects_ambiguous_blocker_and_check_sets(
    mode: str,
    memory_records: tuple[ResearchMemoryRecord, ...],
) -> None:
    checkpoint, _handoff = _selected_recovery_records(memory_records)
    validation = dict(checkpoint.payload["validation"])
    if mode == "unexpected-duplicate":
        validation["unexpected_blockers"] = ["other-blocker", "other-blocker"]
    elif mode == "overlap":
        validation["unexpected_blockers"] = ["iter001-acquisition-contract"]
    else:
        validation["mission_check_ids"] = ["owner-boundary", "owner-boundary"]

    with pytest.raises(ValueError, match=r"unexpected blockers|disjoint|check IDs"):
        handoff_module._CheckpointValidation.model_validate(validation)


def test_handoff_validation_rejects_noncanonical_remaining_gate_set(
    memory_records: tuple[ResearchMemoryRecord, ...],
) -> None:
    _checkpoint, handoff = _selected_recovery_records(memory_records)

    with pytest.raises(ValueError, match="remaining gates differ"):
        handoff_module._HandoffPayload.model_validate(
            {**handoff.payload, "remaining_gates": ["noncanonical gate"]}
        )


def test_snapshot_flags_fail_closed_without_no_follow_support(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delattr(handoff_module.os, "O_DIRECTORY")
    with pytest.raises(HandoffError, match="directory no-follow support"):
        handoff_module._directory_flags()

    monkeypatch.undo()
    monkeypatch.delattr(handoff_module.os, "O_NOFOLLOW")
    with pytest.raises(HandoffError, match="file no-follow support"):
        handoff_module._file_flags()


def test_bounded_directory_names_wraps_enumeration_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_scandir(_descriptor: int) -> object:
        raise OSError("fixture enumeration failure")

    monkeypatch.setattr(handoff_module.os, "scandir", fail_scandir)
    with pytest.raises(HandoffError, match="cannot be enumerated"):
        handoff_module._bounded_directory_names(0, 1, "fixture directory")


@pytest.mark.parametrize("root_failure", [False, True])
def test_directory_snapshot_rejects_unavailable_components(
    root_failure: bool,
    handoff_repo: Path,
    tmp_path: Path,
) -> None:
    root = tmp_path / "absent-root" if root_failure else handoff_repo
    relative = "mission" if root_failure else "mission/absent"

    with pytest.raises(HandoffError, match="unavailable or traverses a symbolic link"):
        handoff_module._directory_snapshot(root, relative, "fixture directory")


def test_directory_snapshot_wraps_descriptor_enumeration_error(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        handoff_module,
        "_bounded_directory_names",
        lambda *_args: (_ for _ in ()).throw(OSError("fixture")),
    )

    with pytest.raises(HandoffError, match="cannot be enumerated"):
        handoff_module._directory_snapshot(handoff_repo, "mission", "fixture directory")


def test_directory_snapshot_rejects_metadata_change_during_enumeration(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def changing_fields(_metadata: object) -> tuple[int, ...]:
        nonlocal calls
        calls += 1
        return (calls,)

    monkeypatch.setattr(handoff_module, "_stable_stat_fields", changing_fields)

    with pytest.raises(HandoffError, match="changed while being enumerated"):
        handoff_module._directory_snapshot(handoff_repo, "mission", "fixture directory")


def test_file_snapshot_rejects_unavailable_root(tmp_path: Path) -> None:
    with pytest.raises(HandoffError, match="is unavailable"):
        handoff_module._read_regular_file(tmp_path / "absent", "README.md", "fixture file")


def test_file_snapshot_wraps_descriptor_read_failure(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        handoff_module.os,
        "fstat",
        lambda _descriptor: (_ for _ in ()).throw(OSError("fixture")),
    )

    with pytest.raises(HandoffError, match="cannot be read"):
        handoff_module._read_regular_file(handoff_repo, "README.md", "fixture file")


def test_file_snapshot_rejects_metadata_change_while_reading(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def changing_fields(_metadata: object) -> tuple[int, ...]:
        nonlocal calls
        calls += 1
        return (calls,)

    monkeypatch.setattr(handoff_module, "_stable_stat_fields", changing_fields)

    with pytest.raises(HandoffError, match="changed while being read"):
        handoff_module._read_regular_file(handoff_repo, "README.md", "fixture file")


def test_recovery_exclusion_policy_covers_root_and_cache_boundaries() -> None:
    assert not handoff_module._is_recovery_excluded(Path("."), directory=True)
    assert handoff_module._is_recovery_excluded(Path(".git"), directory=True)
    assert handoff_module._is_recovery_excluded(Path("nested/__pycache__"), directory=True)


def test_manifest_file_rejects_missing_changed_nonregular_and_oversize_inputs(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor = handoff_module.os.open(handoff_repo, handoff_module._directory_flags())
    try:
        initial = handoff_module.os.stat("README.md", dir_fd=descriptor, follow_symlinks=False)
        with pytest.raises(HandoffError, match="is unavailable"):
            handoff_module._read_manifest_file(
                descriptor,
                "absent.txt",
                Path("absent.txt"),
                initial,
            )
        with pytest.raises(HandoffError, match="changed before reading"):
            handoff_module._read_manifest_file(
                descriptor,
                "README.md",
                Path("README.md"),
                handoff_module.os.stat("mission", dir_fd=descriptor, follow_symlinks=False),
            )
        with pytest.raises(HandoffError, match="must be a regular file"):
            handoff_module._read_manifest_file(
                descriptor,
                "mission",
                Path("mission"),
                handoff_module.os.stat("mission", dir_fd=descriptor, follow_symlinks=False),
            )
        monkeypatch.setattr(handoff_module, "_MAX_INPUT_BYTES", 0)
        with pytest.raises(HandoffError, match="exceeds the per-file limit"):
            handoff_module._read_manifest_file(
                descriptor,
                "README.md",
                Path("README.md"),
                initial,
            )
    finally:
        handoff_module.os.close(descriptor)


def test_manifest_file_wraps_read_error(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor = handoff_module.os.open(handoff_repo, handoff_module._directory_flags())
    initial = handoff_module.os.stat("README.md", dir_fd=descriptor, follow_symlinks=False)
    monkeypatch.setattr(
        handoff_module.os,
        "fdopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("fixture")),
    )
    try:
        with pytest.raises(HandoffError, match="cannot be read"):
            handoff_module._read_manifest_file(
                descriptor,
                "README.md",
                Path("README.md"),
                initial,
            )
    finally:
        handoff_module.os.close(descriptor)


def test_manifest_file_rejects_metadata_change_while_reading(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor = handoff_module.os.open(handoff_repo, handoff_module._directory_flags())
    initial = handoff_module.os.stat("README.md", dir_fd=descriptor, follow_symlinks=False)
    calls = 0

    def changing_fields(_metadata: object) -> tuple[int, ...]:
        nonlocal calls
        calls += 1
        return (1,) if calls <= 2 else (calls,)

    monkeypatch.setattr(handoff_module, "_stable_stat_fields", changing_fields)
    try:
        with pytest.raises(HandoffError, match="changed while being read"):
            handoff_module._read_manifest_file(
                descriptor,
                "README.md",
                Path("README.md"),
                initial,
            )
    finally:
        handoff_module.os.close(descriptor)


def test_recovery_manifest_rejects_excess_depth(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(handoff_module, "_MAX_RECOVERY_INPUT_DEPTH", 0)

    with pytest.raises(HandoffError, match="depth exceeds"):
        handoff_module._recovery_manifest(handoff_repo)


def test_recovery_manifest_wraps_initial_enumeration_oserror(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        handoff_module,
        "_bounded_directory_names",
        lambda *_args: (_ for _ in ()).throw(OSError("fixture")),
    )

    with pytest.raises(HandoffError, match="recovery directory cannot be enumerated"):
        handoff_module._recovery_manifest(handoff_repo)


def test_recovery_manifest_requires_directory_root_metadata(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_metadata = handoff_module.os.stat(handoff_repo / "README.md")
    monkeypatch.setattr(handoff_module.os, "fstat", lambda _descriptor: file_metadata)
    monkeypatch.setattr(handoff_module, "_bounded_directory_names", lambda *_args: ())

    with pytest.raises(HandoffError, match="root must be a directory"):
        handoff_module._recovery_manifest(handoff_repo)


def test_recovery_manifest_wraps_child_inspection_failure(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        handoff_module.os,
        "stat",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("fixture")),
    )

    with pytest.raises(HandoffError, match="recovery input cannot be inspected"):
        handoff_module._recovery_manifest(handoff_repo)


def test_recovery_manifest_rejects_directory_open_failure(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_open = handoff_module.os.open

    def fail_child_directory(
        path: object,
        flags: int,
        *args: object,
        **kwargs: object,
    ) -> int:
        if path == ".github":
            raise OSError("fixture")
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(handoff_module.os, "open", fail_child_directory)

    with pytest.raises(HandoffError, match="recovery directory traverses a symbolic link"):
        handoff_module._recovery_manifest(handoff_repo)


def test_recovery_manifest_rejects_directory_change_before_traversal(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_open = handoff_module.os.open

    def change_after_open(
        path: object,
        flags: int,
        *args: object,
        **kwargs: object,
    ) -> int:
        descriptor = original_open(path, flags, *args, **kwargs)
        if path == ".github":
            (handoff_repo / ".github" / "post-open-race.txt").write_text(
                "changed\n", encoding="utf-8"
            )
        return descriptor

    monkeypatch.setattr(handoff_module.os, "open", change_after_open)

    with pytest.raises(HandoffError, match="changed before traversal"):
        handoff_module._recovery_manifest(handoff_repo)


def test_recovery_manifest_rejects_directory_change_after_traversal(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_stat = handoff_module.os.stat
    root_descriptor: int | None = None
    observations = 0

    def changing_stat(
        path: object,
        *args: object,
        **kwargs: object,
    ) -> object:
        nonlocal observations, root_descriptor
        directory_descriptor = kwargs.get("dir_fd")
        if path == ".github":
            if root_descriptor is None:
                root_descriptor = int(directory_descriptor)
            if directory_descriptor == root_descriptor:
                observations += 1
                if observations == 2:
                    (handoff_repo / ".github" / "post-traversal-race.txt").write_text(
                        "changed\n", encoding="utf-8"
                    )
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(handoff_module.os, "stat", changing_stat)

    with pytest.raises(HandoffError, match=r"changed during traversal: \.github"):
        handoff_module._recovery_manifest(handoff_repo)


@pytest.mark.parametrize(
    ("limit_name", "message"),
    [
        ("_MAX_RECOVERY_INPUT_FILES", "file count exceeds"),
        ("_MAX_RECOVERY_INPUT_BYTES", "bytes exceed"),
    ],
)
def test_recovery_manifest_rejects_file_and_byte_limit_overflow(
    limit_name: str,
    message: str,
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(handoff_module, limit_name, 0)

    with pytest.raises(HandoffError, match=message):
        handoff_module._recovery_manifest(handoff_repo)


def test_recovery_manifest_rejects_special_file(
    handoff_repo: Path,
) -> None:
    handoff_module.os.mkfifo(handoff_repo / "adversarial.pipe")

    with pytest.raises(HandoffError, match="regular file or directory"):
        handoff_module._recovery_manifest(handoff_repo)


def test_recovery_manifest_wraps_resnapshot_oserror(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "empty-recovery-root"
    root.mkdir()
    calls = 0

    def fail_resnapshot(*_args: object) -> tuple[str, ...]:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("fixture")
        return ()

    monkeypatch.setattr(handoff_module, "_bounded_directory_names", fail_resnapshot)

    with pytest.raises(HandoffError, match="cannot be resnapshotted"):
        handoff_module._recovery_manifest(root)


def test_recovery_manifest_rejects_changed_root_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "empty-recovery-root"
    root.mkdir()
    calls = 0

    def change_resnapshot(*_args: object) -> tuple[str, ...]:
        nonlocal calls
        calls += 1
        return () if calls == 1 else ("appeared",)

    monkeypatch.setattr(handoff_module, "_bounded_directory_names", change_resnapshot)

    with pytest.raises(HandoffError, match=r"changed during traversal: \."):
        handoff_module._recovery_manifest(root)


def test_recovery_manifest_rejects_unavailable_root(tmp_path: Path) -> None:
    with pytest.raises(HandoffError, match="root is unavailable"):
        handoff_module._recovery_manifest(tmp_path / "absent-root")


def test_bound_module_verification_rejects_identity_substitution(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = handoff_module._BOUND_FIELDTRUE_MODULES[0]
    monkeypatch.setitem(sys.modules, binding.name, ModuleType(binding.name))

    with pytest.raises(HandoffError, match="bound Fieldtrue module identity changed"):
        handoff_module._verify_bound_module_sources(handoff_repo)


def test_bound_module_verification_wraps_compile_failure(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_compile(*_args: object, **_kwargs: object) -> object:
        raise SyntaxError("fixture")

    monkeypatch.setattr(handoff_module, "compile", fail_compile, raising=False)

    with pytest.raises(HandoffError, match="source cannot be compiled"):
        handoff_module._verify_bound_module_sources(handoff_repo)


def test_module_population_rejects_bound_identity_substitution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = handoff_module._BOUND_FIELDTRUE_MODULES[0]
    initial_modules = handoff_module._loaded_fieldtrue_modules()
    monkeypatch.setitem(sys.modules, binding.name, ModuleType(binding.name))

    with pytest.raises(HandoffError, match="preloaded Fieldtrue module identity changed"):
        handoff_module._verify_module_population(initial_modules)


def test_module_population_rejects_ambient_identity_substitution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    name = "fieldtrue.preloaded_ambient_fixture"
    monkeypatch.setitem(sys.modules, name, ModuleType(name))
    initial_modules = handoff_module._loaded_fieldtrue_modules()
    monkeypatch.setitem(sys.modules, name, ModuleType(name))

    with pytest.raises(HandoffError, match="preloaded Fieldtrue module identity changed"):
        handoff_module._verify_module_population(initial_modules)


@pytest.mark.parametrize("invalid", [None, object()])
def test_loaded_module_population_rejects_nonmodule_entries(
    invalid: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "fieldtrue.invalid_population_fixture", invalid)

    with pytest.raises(HandoffError, match="invalid loaded Fieldtrue module entries"):
        handoff_module._loaded_fieldtrue_modules()


def test_json_and_required_string_accept_finite_scalar_and_reject_empty_value() -> None:
    assert handoff_module._finite_json_float("1.25", "fixture") == 1.25
    with pytest.raises(HandoffError, match="must be a nonempty string"):
        handoff_module._required_string({"field": ""}, "field", "fixture")


def test_render_rejects_unbound_recovery_evidence_uri(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint, _handoff = _selected_recovery_records(memory_records)
    evidence = tuple(
        item.model_copy(update={"uri": "https://example.invalid/substitution"})
        if index == 0
        else item
        for index, item in enumerate(checkpoint.evidence)
    )
    records = _replace_record(memory_records, checkpoint.event_id, evidence=evidence)
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(HandoffError, match="not commit and byte bound"):
        render_handoff(handoff_repo)


def test_render_rejects_recovery_memory_identity_drift(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint, _handoff = _selected_recovery_records(memory_records)
    records = _replace_record(memory_records, checkpoint.event_id, mission_id="different-mission")
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(HandoffError, match="current Inbar memory identity"):
        render_handoff(handoff_repo)


def test_render_accepts_frozen_legacy_recovery_contract(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy_records = _legacy_recovery_memory(memory_records)
    _install_verified_dependencies(monkeypatch, legacy_records)

    document = render_handoff(handoff_repo).decode("utf-8")

    assert f"Active handoff: `{_LEGACY_HANDOFF_EVENT_ID}`" in document
    assert f"Checkpoint event: `{_LEGACY_CHECKPOINT_EVENT_ID}`" in document
    assert "This frozen legacy list is non-exhaustive." in document


def test_render_rejects_legacy_recovery_contract_drift(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy_records = _legacy_recovery_memory(memory_records)
    records = _replace_record(legacy_records, _LEGACY_CHECKPOINT_EVENT_ID, stage="mission-handoff")
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(HandoffError, match="legacy recovery pair differs"):
        render_handoff(handoff_repo)


@pytest.mark.parametrize("mode", ["missing", "mismatch"])
def test_render_rejects_unavailable_or_mismatched_imported_renderer_bytes(
    mode: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    imported = None if mode == "missing" else b"different imported renderer"
    monkeypatch.setattr(handoff_module, "_IMPORTED_RENDERER_BYTES", imported)

    with pytest.raises(
        HandoffError,
        match=r"source bytes are unavailable|source differs from repository source",
    ):
        render_handoff(handoff_repo)


@pytest.mark.parametrize("mode", ["compile-error", "code-mismatch"])
def test_render_rejects_final_renderer_compilation_substitution(
    mode: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    original_compile = compile
    calls = 0
    loaded_modules = handoff_module._loaded_fieldtrue_modules()
    verified_module_compilations = len(handoff_module._BOUND_FIELDTRUE_MODULES) + len(
        loaded_modules.keys() & handoff_module._HANDOFF_ALLOWED_PRELOADED_MODULE_NAMES
    )

    def substituted_compile(
        source: object,
        filename: str,
        compile_mode: str,
        *args: object,
        **kwargs: object,
    ) -> object:
        nonlocal calls
        calls += 1
        if calls <= verified_module_compilations:
            return original_compile(source, filename, compile_mode, *args, **kwargs)
        if mode == "compile-error":
            raise SyntaxError("fixture")
        return original_compile("VALUE = 1\n", filename, compile_mode, *args, **kwargs)

    monkeypatch.setattr(handoff_module, "compile", substituted_compile, raising=False)

    with pytest.raises(
        HandoffError,
        match=r"renderer source cannot be compiled|renderer code differs",
    ):
        render_handoff(handoff_repo)


def test_render_rejects_bound_source_map_change_at_terminal_boundary(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint, handoff = _versioned_recovery_records(memory_records)
    _install_verified_dependencies(monkeypatch, (*memory_records, checkpoint, handoff))
    original = handoff_module._verify_bound_module_sources
    calls = 0

    def changed_final_map(repo_root: Path) -> dict[str, str]:
        nonlocal calls
        calls += 1
        hashes = original(repo_root)
        if calls == 2:
            first = next(iter(hashes))
            hashes[first] = "0" * 64
        return hashes

    monkeypatch.setattr(handoff_module, "_verify_bound_module_sources", changed_final_map)

    with pytest.raises(HandoffError, match="module sources changed during handoff"):
        render_handoff(handoff_repo)
    assert calls == 2


def test_versioned_render_rejects_mission_check_id_drift(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint, handoff = _versioned_recovery_records(memory_records)
    validation = {
        **checkpoint.payload["validation"],
        "mission_check_ids": [
            *handoff_module._EXPECTED_MISSION_CHECK_IDS[:-1],
            "substituted-provider-check",
        ],
    }
    checkpoint = checkpoint.model_copy(
        update={"payload": {**checkpoint.payload, "validation": validation}}
    )
    _install_verified_dependencies(monkeypatch, (*memory_records, checkpoint, handoff))

    with pytest.raises(HandoffError, match="mission check IDs differ"):
        render_handoff(handoff_repo)


def test_render_rejects_nonobject_publication_transition(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    loop_path = handoff_repo / "mission" / "loop.json"
    loop = json.loads(loop_path.read_text(encoding="utf-8"))
    loop["publication_transition"] = "blocked"
    loop_path.write_text(json.dumps(loop, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(HandoffError, match="publication transition must be an object"):
        render_handoff(handoff_repo)


def test_render_rejects_renderer_change_during_final_snapshot(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    original_read = handoff_module._read_regular_file
    renderer_reads = 0

    def changing_read(repo_root: Path, relative: str, label: str) -> bytes:
        nonlocal renderer_reads
        data = original_read(repo_root, relative, label)
        if label == handoff_module._RENDERER_PATH:
            renderer_reads += 1
            if renderer_reads == 2:
                return data + b"# concurrent renderer substitution\n"
        return data

    monkeypatch.setattr(handoff_module, "_read_regular_file", changing_read)

    with pytest.raises(HandoffError, match="renderer changed during rendering"):
        render_handoff(handoff_repo)
