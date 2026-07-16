from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

import fieldtrue.memory as memory_module
from fieldtrue.canonical import CanonicalizationError, canonical_json, sha256_value
from fieldtrue.memory import (
    AccessClass,
    EpistemicPhase,
    LabelAccess,
    MemoryActor,
    MemoryEventType,
    MemoryEvidenceRef,
    MemoryStatus,
    MemoryVerificationError,
    ResearchMemoryRecord,
    append_memory,
    load_memory_records,
    load_memory_records_bytes,
    verify_memory,
    verify_memory_prefix,
)

COMMIT = "1" * 40
ACTOR = MemoryActor(kind="agent", actor_id="codex")


def _append(path: Path, event_id: str, **overrides: object) -> None:
    values: dict[str, object] = {
        "event_id": event_id,
        "stage": "launch",
        "epistemic_phase": EpistemicPhase.PROSPECTIVE,
        "actor": ACTOR,
        "event_type": MemoryEventType.DECISION,
        "status": MemoryStatus.RECORDED,
        "summary": "A research decision",
        "payload": {"decision": "proceed"},
        "source_commit": COMMIT,
    }
    values.update(overrides)
    append_memory(path, **values)  # type: ignore[arg-type]


def test_memory_chain_and_correction_are_append_only(tmp_path: Path) -> None:
    path = tmp_path / "memory.jsonl"
    _append(path, "decision-1")
    _append(
        path,
        "correction-1",
        event_type=MemoryEventType.CORRECTION,
        epistemic_phase=EpistemicPhase.RETROSPECTIVE,
        status=MemoryStatus.RECORDED,
        corrects_event_id="decision-1",
        summary="Correct an earlier statement",
        payload={"old": "x", "corrected": "y"},
    )
    count, head = verify_memory(path)
    assert count == 2
    assert len(head) == 64


def test_memory_identity_transition_is_versioned_and_one_way(tmp_path: Path) -> None:
    path = tmp_path / "memory.jsonl"
    _append(path, "legacy-decision")
    legacy = json.loads(path.read_text(encoding="utf-8"))
    legacy["schema_version"] = "daniel.research-memory.v1"
    legacy["mission_id"] = "fieldtrue"
    legacy_body = {key: value for key, value in legacy.items() if key != "event_hash"}
    legacy["event_hash"] = sha256_value(legacy_body)
    path.write_bytes(canonical_json(legacy) + b"\n")

    _append(path, "inbar-decision")
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert records[0]["schema_version"] == "daniel.research-memory.v1"
    assert records[0]["mission_id"] == "fieldtrue"
    assert records[1]["schema_version"] == "daniel.research-memory.v2"
    assert records[1]["mission_id"] == "inbar"
    assert verify_memory(path)[0] == 2

    with pytest.raises(ValidationError, match="identity"):
        ResearchMemoryRecord.model_validate(
            {**records[1], "schema_version": "daniel.research-memory.v1"}
        )

    regression = {
        **records[1],
        "schema_version": "daniel.research-memory.v1",
        "mission_id": "fieldtrue",
        "sequence": 2,
        "event_id": "legacy-regression",
        "previous_event_hash": records[1]["event_hash"],
    }
    regression_body = {key: value for key, value in regression.items() if key != "event_hash"}
    regression["event_hash"] = sha256_value(regression_body)
    with path.open("ab") as handle:
        handle.write(canonical_json(regression) + b"\n")
    with pytest.raises(MemoryVerificationError, match="cannot resume"):
        verify_memory(path)


def test_memory_rejects_unknown_correction_and_duplicate_id(tmp_path: Path) -> None:
    path = tmp_path / "memory.jsonl"
    with pytest.raises(MemoryVerificationError, match="earlier"):
        _append(
            path,
            "correction-1",
            event_type=MemoryEventType.CORRECTION,
            corrects_event_id="missing",
        )
    _append(path, "decision-1")
    with pytest.raises(MemoryVerificationError, match="duplicate"):
        _append(path, "decision-1")


def test_memory_requires_recurrence_for_manual_work_and_rejects_sensitive_payload(
    tmp_path: Path,
) -> None:
    path = tmp_path / "memory.jsonl"
    now = datetime.now(UTC)
    with pytest.raises(ValidationError, match="recurrence"):
        append_memory(
            path,
            event_id="manual-1",
            stage="launch",
            epistemic_phase=EpistemicPhase.RETROSPECTIVE,
            actor=ACTOR,
            event_type=MemoryEventType.MANUAL_WORK,
            status=MemoryStatus.RECORDED,
            summary="Manual work",
            payload={"steps": 3},
            source_commit=COMMIT,
            occurred_at=now,
            recorded_at=now,
        )
    with pytest.raises(ValidationError, match="sensitive"):
        append_memory(
            path,
            event_id="bad-secret",
            stage="launch",
            epistemic_phase=EpistemicPhase.RETROSPECTIVE,
            actor=ACTOR,
            event_type=MemoryEventType.FINDING,
            status=MemoryStatus.RECORDED,
            summary="Bad payload",
            payload={"finding": "Sensitive value", "api_token": "must-not-be-here"},
            source_commit=COMMIT,
            occurred_at=now,
            recorded_at=now,
        )


def test_memory_rejects_recording_before_occurrence(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValidationError, match="before"):
        _append(
            tmp_path / "memory.jsonl",
            "time-error",
            occurred_at=now,
            recorded_at=now - timedelta(seconds=1),
        )


def test_memory_tampering_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "memory.jsonl"
    _append(path, "decision-1", access=AccessClass.INTERNAL)
    record = json.loads(path.read_text())
    record["summary"] = "rewritten"
    path.write_text(json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n")
    with pytest.raises(MemoryVerificationError, match="hash"):
        verify_memory(path)


def test_empty_memory_is_valid(tmp_path: Path) -> None:
    assert verify_memory(tmp_path / "absent.jsonl") == (0, "0" * 64)


def test_memory_records_can_be_verified_from_one_byte_snapshot(tmp_path: Path) -> None:
    path = tmp_path / "memory.jsonl"
    _append(path, "decision-1")
    records = load_memory_records_bytes(path.read_bytes())
    assert [record.event_id for record in records] == ["decision-1"]
    with pytest.raises(MemoryVerificationError, match="UTF-8"):
        load_memory_records_bytes(b"\xff")


@pytest.mark.parametrize(
    "mutation",
    [
        lambda line: line.replace(b'{"access":', b'{"summary":"forged","access":', 1),
        lambda line: line.replace(
            b'"actor":{"actor_id":', b'"actor":{"kind":"human","actor_id":', 1
        ),
    ],
)
def test_memory_snapshot_rejects_duplicate_keys_at_every_depth(
    mutation: object,
    tmp_path: Path,
) -> None:
    path = tmp_path / "memory.jsonl"
    _append(path, "decision-1")
    duplicate = mutation(path.read_bytes())  # type: ignore[operator]

    with pytest.raises(MemoryVerificationError, match="duplicate memory object key"):
        load_memory_records_bytes(duplicate)


def test_memory_snapshot_rejects_duplicate_keys_inside_nested_lists(tmp_path: Path) -> None:
    path = tmp_path / "memory.jsonl"
    _append(
        path,
        "decision-1",
        payload={"decision": "proceed", "items": [{"role": "source"}]},
    )
    duplicate = path.read_bytes().replace(
        b'"items":[{"role":"source"}]',
        b'"items":[{"role":"source","role":"source"}]',
        1,
    )

    with pytest.raises(MemoryVerificationError, match="duplicate memory object key"):
        load_memory_records_bytes(duplicate)


def test_memory_snapshot_requires_canonical_jsonl(tmp_path: Path) -> None:
    path = tmp_path / "memory.jsonl"
    _append(path, "decision-1")

    with pytest.raises(MemoryVerificationError, match="noncanonical memory line at 1"):
        load_memory_records_bytes(path.read_bytes().replace(b'"access":', b' "access":', 1))

    non_finite = path.read_bytes().replace(b'"manual_minutes":0.0', b'"manual_minutes":NaN', 1)
    with pytest.raises(MemoryVerificationError, match="non-finite memory number"):
        load_memory_records_bytes(non_finite)


def test_nonempty_memory_requires_a_terminal_lf_before_verify_or_append(
    tmp_path: Path,
) -> None:
    path = tmp_path / "memory.jsonl"
    _append(path, "decision-1")
    path.write_bytes(path.read_bytes().removesuffix(b"\n"))

    with pytest.raises(MemoryVerificationError, match="must end with one LF"):
        verify_memory(path)
    with pytest.raises(MemoryVerificationError, match="must end with one LF"):
        _append(path, "decision-2")

    path.write_bytes(path.read_bytes() + b"\n")
    _append(path, "decision-2")
    assert verify_memory(path)[0] == 2


@pytest.mark.parametrize(
    "mutation",
    [
        lambda data: data.replace(b"\n", b"\r\n"),
        lambda data: data.removesuffix(b"\n") + b"\r\n",
    ],
)
def test_memory_rejects_crlf_framing(mutation: object, tmp_path: Path) -> None:
    path = tmp_path / "memory.jsonl"
    _append(path, "decision-1")
    path.write_bytes(mutation(path.read_bytes()))  # type: ignore[operator]

    with pytest.raises(MemoryVerificationError, match="exact LF framing"):
        load_memory_records_bytes(path.read_bytes())
    with pytest.raises(MemoryVerificationError, match="exact LF framing"):
        verify_memory(path)
    with pytest.raises(MemoryVerificationError, match="exact LF framing"):
        _append(path, "decision-2")


def test_memory_prefix_is_immutable_and_current_chain_is_reverified(tmp_path: Path) -> None:
    current = tmp_path / "current.jsonl"
    _append(current, "decision-1")
    base = tmp_path / "base.jsonl"
    base.write_bytes(current.read_bytes())
    _append(current, "decision-2")
    assert verify_memory_prefix(base, current) == (1, 2)

    rewritten = current.read_bytes().replace(b"decision-1", b"decision-x", 1)
    current.write_bytes(rewritten)
    with pytest.raises(MemoryVerificationError, match="immutable prefix"):
        verify_memory_prefix(base, current)
    with pytest.raises(MemoryVerificationError, match="hash"):
        _append(current, "decision-3")
    with pytest.raises(MemoryVerificationError, match="base memory"):
        verify_memory_prefix(tmp_path / "missing", current)


def test_memory_event_type_and_timestamp_semantics_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "memory.jsonl"
    _append(path, "decision-1")
    with pytest.raises(ValidationError, match="only correction"):
        _append(path, "bad-link", corrects_event_id="decision-1")
    with pytest.raises(CanonicalizationError, match="naive datetimes"):
        _append(
            tmp_path / "naive.jsonl",
            "naive",
            occurred_at=datetime.fromisoformat("2026-01-01"),
            recorded_at=datetime.fromisoformat("2026-01-01"),
        )
    with pytest.raises(ValidationError, match="sensitive"):
        _append(
            tmp_path / "nested.jsonl",
            "nested-secret",
            payload={
                "decision": "Inspect nested fields",
                "items": [{"private_key": "forbidden"}],
            },
        )


def test_memory_evidence_and_links_require_reconstructible_anchors(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="content hash"):
        MemoryEvidenceRef(
            role="source",
            uri="https://example.invalid/paper",
            media_type="text/html",
            access=AccessClass.PUBLIC,
            label_access=LabelAccess.NONE,
        )
    external = MemoryEvidenceRef(
        role="source",
        uri="https://example.invalid/paper",
        sha256="a" * 64,
        media_type="text/html",
        access=AccessClass.PUBLIC,
        label_access=LabelAccess.NONE,
    )
    assert external.git_commit is None
    with pytest.raises(ValidationError, match="must not include a Git commit"):
        MemoryEvidenceRef(
            role="source",
            uri="https://example.invalid/paper",
            sha256="a" * 64,
            git_commit=COMMIT,
            media_type="text/html",
            access=AccessClass.PUBLIC,
            label_access=LabelAccess.NONE,
        )
    with pytest.raises(ValidationError, match="Git commit"):
        MemoryEvidenceRef(
            role="input",
            uri="docs/protocol.md",
            sha256="a" * 64,
            media_type="text/markdown",
            access=AccessClass.INTERNAL,
            label_access=LabelAccess.NONE,
        )
    with pytest.raises(ValidationError, match="cannot be public"):
        MemoryEvidenceRef(
            role="input",
            uri="sealed/cases.jsonl",
            git_commit=COMMIT,
            media_type="application/jsonl",
            access=AccessClass.PUBLIC,
            label_access=LabelAccess.SEALED_HELDOUT,
        )
    for uri in (
        "https://example.invalid/paper?revision=1",
        "https://example.invalid/paper?",
        "https://example.invalid/paper#results",
        "https://example.invalid/paper#",
    ):
        with pytest.raises(ValidationError, match="query or fragment"):
            MemoryEvidenceRef(
                role="source",
                uri=uri,
                sha256="a" * 64,
                media_type="text/html",
                access=AccessClass.PUBLIC,
                label_access=LabelAccess.NONE,
            )

    path = tmp_path / "memory.jsonl"
    _append(path, "decision-1")
    with pytest.raises(MemoryVerificationError, match="links"):
        _append(path, "decision-2", links={"supports": "missing-event"})


def test_memory_evidence_schema_separates_external_and_repository_anchors() -> None:
    schema = MemoryEvidenceRef.model_json_schema()
    external, repository = schema["allOf"][0]["oneOf"]

    assert set(external["required"]) == {"uri", "sha256"}
    assert external["properties"]["uri"] == {
        "type": "string",
        "pattern": r"^https://[^/?#]+(?:/|$)",
    }
    assert external["properties"]["sha256"] == {"type": "string"}
    assert external["properties"]["git_commit"] == {"type": "null"}
    assert set(repository["required"]) == {"uri", "git_commit"}
    assert repository["properties"]["uri"] == {
        "type": "string",
        "not": {"pattern": r"^[A-Za-z][A-Za-z0-9+.-]*:"},
    }
    assert repository["properties"]["git_commit"] == {"type": "string"}


def test_memory_event_payload_contract_is_typed(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="lacks required fields"):
        _append(
            tmp_path / "memory.jsonl",
            "finding-without-finding",
            event_type=MemoryEventType.FINDING,
            payload={"observation": "untyped"},
        )


@pytest.mark.parametrize("alias_kind", ["symlink", "hardlink"])
def test_memory_file_apis_reject_final_path_aliases(
    alias_kind: str,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.jsonl"
    _append(source, "decision-1")
    alias = tmp_path / "alias.jsonl"
    if alias_kind == "symlink":
        alias.symlink_to(source)
    else:
        os.link(source, alias)

    with pytest.raises(MemoryVerificationError, match=r"symbolic link|hard linked"):
        verify_memory(alias)
    with pytest.raises(MemoryVerificationError, match=r"symbolic link|hard linked"):
        load_memory_records(alias)
    with pytest.raises(MemoryVerificationError, match=r"symbolic link|hard linked"):
        verify_memory_prefix(alias, source)
    with pytest.raises(MemoryVerificationError, match=r"symbolic link|hard linked"):
        verify_memory_prefix(source, alias)
    with pytest.raises(MemoryVerificationError, match=r"symbolic link|hard linked"):
        _append(alias, "decision-2")


def test_memory_file_reads_and_append_are_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "memory.jsonl"
    _append(path, "decision-1")
    monkeypatch.setattr(memory_module, "_MAX_MEMORY_BYTES", path.stat().st_size - 1)

    with pytest.raises(MemoryVerificationError, match="byte limit"):
        verify_memory(path)
    with pytest.raises(MemoryVerificationError, match="byte limit"):
        load_memory_records(path)
    with pytest.raises(MemoryVerificationError, match="byte limit"):
        verify_memory_prefix(path, path)
    with pytest.raises(MemoryVerificationError, match="byte limit"):
        _append(path, "decision-2")
