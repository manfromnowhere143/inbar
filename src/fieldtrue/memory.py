"""Append-only extraction memory for the future standalone research engine."""

from __future__ import annotations

import fcntl
import os
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Self
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from fieldtrue.canonical import canonical_json, sha256_value
from fieldtrue.domain import GitObjectId, Identifier, Sha256

MEMORY_GENESIS_HASH = "0" * 64
_SENSITIVE_KEY_TERMS = ("credential", "hidden_label", "password", "private_key", "secret", "token")


class MemoryVerificationError(ValueError):
    pass


class MemoryEventType(StrEnum):
    SOURCE = "source"
    DECISION = "decision"
    PROTOCOL = "protocol"
    EXECUTION = "execution"
    FINDING = "finding"
    FAILURE = "failure"
    CORRECTION = "correction"
    RESOURCE = "resource"
    MANUAL_WORK = "manual_work"
    HANDOFF = "handoff"
    NAMING = "naming"


class EpistemicPhase(StrEnum):
    PROSPECTIVE = "prospective"
    EXPLORATORY = "exploratory"
    RETROSPECTIVE = "retrospective"


class MemoryStatus(StrEnum):
    PENDING = "pending"
    RECORDED = "recorded"
    PASS = "pass"  # noqa: S105 - research status, not a credential
    NEGATIVE = "negative"
    NULL = "null"
    BLOCKED = "blocked"
    INVALID = "invalid"
    VOID = "void"
    INTERRUPTED = "interrupted"
    SUPERSEDED = "superseded"


class AccessClass(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    RESTRICTED = "restricted"


class LabelAccess(StrEnum):
    NONE = "none"
    DEVELOPMENT = "development"
    SEALED_HELDOUT = "sealed_heldout"


class MemoryActor(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: str = Field(pattern=r"^(human|agent|system)$")
    actor_id: Identifier


class MemoryEvidenceRef(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    role: str = Field(pattern=r"^(input|raw|derived|verifier|source|approval)$")
    uri: str = Field(min_length=1)
    sha256: Sha256 | None = None
    git_commit: GitObjectId | None = None
    media_type: str = Field(min_length=1)
    access: AccessClass
    label_access: LabelAccess

    @model_validator(mode="after")
    def evidence_is_content_or_git_anchored(self) -> Self:
        parsed = urlsplit(self.uri)
        if parsed.scheme:
            if parsed.scheme != "https" or not parsed.hostname:
                raise ValueError("external memory evidence must use HTTPS")
            if parsed.username is not None or parsed.password is not None:
                raise ValueError("memory evidence URI must not contain credentials")
            if self.sha256 is None:
                raise ValueError("external memory evidence requires a content hash")
        else:
            pure = PurePosixPath(self.uri)
            if pure.is_absolute() or ".." in pure.parts:
                raise ValueError("repository memory evidence path is unsafe")
            if self.git_commit is None:
                raise ValueError("repository memory evidence requires a Git commit")
        if self.sha256 is None and self.git_commit is None:
            raise ValueError("memory evidence requires a content or Git anchor")
        if self.access == AccessClass.PUBLIC and self.label_access == LabelAccess.SEALED_HELDOUT:
            raise ValueError("sealed held-out evidence cannot be public")
        return self


_REQUIRED_PAYLOAD_FIELDS: dict[MemoryEventType, frozenset[str]] = {
    MemoryEventType.SOURCE: frozenset({"source"}),
    MemoryEventType.DECISION: frozenset({"decision"}),
    MemoryEventType.PROTOCOL: frozenset({"protocol"}),
    MemoryEventType.EXECUTION: frozenset({"action", "outcome"}),
    MemoryEventType.FINDING: frozenset({"finding"}),
    MemoryEventType.FAILURE: frozenset({"failure"}),
    MemoryEventType.CORRECTION: frozenset({"old", "corrected"}),
    MemoryEventType.RESOURCE: frozenset({"resource"}),
    MemoryEventType.MANUAL_WORK: frozenset({"task"}),
    MemoryEventType.HANDOFF: frozenset({"state", "next_action"}),
    MemoryEventType.NAMING: frozenset({"candidate", "verdict"}),
}


class ResearchMemoryRecord(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        json_schema_extra={
            "allOf": [
                {
                    "oneOf": [
                        {
                            "properties": {
                                "schema_version": {"const": "daniel.research-memory.v1"},
                                "mission_id": {"const": "fieldtrue"},
                            }
                        },
                        {
                            "properties": {
                                "schema_version": {"const": "daniel.research-memory.v2"},
                                "mission_id": {"const": "inbar"},
                            }
                        },
                    ]
                }
            ]
        },
    )

    schema_version: Literal["daniel.research-memory.v1", "daniel.research-memory.v2"] = (
        "daniel.research-memory.v2"
    )
    mission_id: Literal["fieldtrue", "inbar"] = "inbar"
    sequence: int = Field(ge=0)
    event_id: Identifier
    occurred_at: datetime
    recorded_at: datetime
    stage: str = Field(min_length=1)
    epistemic_phase: EpistemicPhase
    actor: MemoryActor
    event_type: MemoryEventType
    status: MemoryStatus
    summary: str = Field(min_length=1)
    payload: dict[str, Any]
    evidence: tuple[MemoryEvidenceRef, ...] = ()
    links: dict[Identifier, Identifier] = Field(default_factory=dict)
    access: AccessClass = AccessClass.INTERNAL
    source_commit: GitObjectId
    manual_minutes: float = Field(default=0.0, ge=0.0)
    cost_usd: str = Field(default="0", pattern=r"^(0|[1-9][0-9]*)(\.[0-9]{1,6})?$")
    recurrence_key: Identifier | None = None
    engine_requirement: str | None = None
    corrects_event_id: Identifier | None = None
    previous_event_hash: Sha256
    event_hash: Sha256

    @model_validator(mode="after")
    def occurred_at_is_aware(self) -> Self:
        identity_versions = {
            ("daniel.research-memory.v1", "fieldtrue"),
            ("daniel.research-memory.v2", "inbar"),
        }
        if (self.schema_version, self.mission_id) not in identity_versions:
            raise ValueError("research-memory schema and mission identity do not match")
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() is None:
            raise ValueError("memory timestamp must be timezone-aware")
        if self.recorded_at.tzinfo is None or self.recorded_at.utcoffset() is None:
            raise ValueError("memory recording timestamp must be timezone-aware")
        if self.recorded_at < self.occurred_at:
            raise ValueError("memory cannot be recorded before it occurred")
        if self.event_type == MemoryEventType.CORRECTION and self.corrects_event_id is None:
            raise ValueError("correction events require corrects_event_id")
        if self.event_type != MemoryEventType.CORRECTION and self.corrects_event_id is not None:
            raise ValueError("only correction events may set corrects_event_id")
        if self.event_type == MemoryEventType.MANUAL_WORK and self.recurrence_key is None:
            raise ValueError("manual-work events require a recurrence key")
        missing = _REQUIRED_PAYLOAD_FIELDS[self.event_type] - set(self.payload)
        if missing:
            raise ValueError(
                f"{self.event_type.value} memory payload lacks required fields: {sorted(missing)}"
            )
        _reject_sensitive_payload_keys(self.payload)
        return self


def _reject_sensitive_payload_keys(value: Any, path: str = "payload") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = key.casefold()
            is_reference = normalized.endswith(("_ref", "_reference", "_hash"))
            if not is_reference and any(term in normalized for term in _SENSITIVE_KEY_TERMS):
                raise ValueError(f"sensitive memory field is forbidden: {path}.{key}")
            _reject_sensitive_payload_keys(item, f"{path}.{key}")
    elif isinstance(value, list | tuple):
        for index, item in enumerate(value):
            _reject_sensitive_payload_keys(item, f"{path}[{index}]")


def _record_body(record: ResearchMemoryRecord | dict[str, Any]) -> dict[str, Any]:
    body = (
        record.model_dump(mode="json") if isinstance(record, ResearchMemoryRecord) else dict(record)
    )
    body.pop("event_hash", None)
    return body


def _parse_memory(text: str) -> list[ResearchMemoryRecord]:
    records: list[ResearchMemoryRecord] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            raise MemoryVerificationError(f"blank memory line at {line_number}")
        try:
            records.append(ResearchMemoryRecord.model_validate_json(line))
        except ValueError as error:
            raise MemoryVerificationError(f"invalid memory line {line_number}") from error
    return records


def _verify_records(records: list[ResearchMemoryRecord]) -> tuple[int, str]:
    previous = MEMORY_GENESIS_HASH
    identifiers: set[str] = set()
    inbar_identity_started = False
    for sequence, record in enumerate(records):
        if record.sequence != sequence:
            raise MemoryVerificationError("memory sequence is not contiguous")
        if record.event_id in identifiers:
            raise MemoryVerificationError(f"duplicate memory event ID: {record.event_id}")
        if record.corrects_event_id is not None and record.corrects_event_id not in identifiers:
            raise MemoryVerificationError("correction must reference an earlier memory event")
        unknown_links = set(record.links.values()) - identifiers
        if unknown_links:
            raise MemoryVerificationError("memory links must reference earlier events")
        if record.previous_event_hash != previous:
            raise MemoryVerificationError("memory predecessor hash mismatch")
        if sha256_value(_record_body(record)) != record.event_hash:
            raise MemoryVerificationError("memory event hash mismatch")
        if record.mission_id == "inbar":
            inbar_identity_started = True
        elif inbar_identity_started:
            raise MemoryVerificationError(
                "legacy mission identity cannot resume after the Inbar transition"
            )
        identifiers.add(record.event_id)
        previous = record.event_hash
    return len(records), previous


def verify_memory(path: Path) -> tuple[int, str]:
    if not path.exists():
        return 0, MEMORY_GENESIS_HASH
    return _verify_records(_parse_memory(path.read_text(encoding="utf-8")))


def load_memory_records(path: Path) -> tuple[ResearchMemoryRecord, ...]:
    if not path.is_file():
        return ()
    records = _parse_memory(path.read_text(encoding="utf-8"))
    _verify_records(records)
    return tuple(records)


def verify_memory_prefix(base_path: Path, current_path: Path) -> tuple[int, int]:
    if not base_path.is_file():
        raise MemoryVerificationError("base memory ledger is missing")
    base_lines = base_path.read_bytes().splitlines(keepends=True)
    current_lines = current_path.read_bytes().splitlines(keepends=True)
    if current_lines[: len(base_lines)] != base_lines:
        raise MemoryVerificationError("base memory ledger is not an immutable prefix")
    base_count, _ = verify_memory(base_path)
    current_count, _ = verify_memory(current_path)
    return base_count, current_count


def append_memory(
    path: Path,
    *,
    event_id: Identifier,
    stage: str,
    epistemic_phase: EpistemicPhase,
    actor: MemoryActor,
    event_type: MemoryEventType,
    status: MemoryStatus,
    summary: str,
    payload: dict[str, Any],
    source_commit: GitObjectId,
    evidence: tuple[MemoryEvidenceRef, ...] = (),
    links: dict[Identifier, Identifier] | None = None,
    access: AccessClass = AccessClass.INTERNAL,
    manual_minutes: float = 0.0,
    cost_usd: str = "0",
    recurrence_key: Identifier | None = None,
    engine_requirement: str | None = None,
    corrects_event_id: Identifier | None = None,
    occurred_at: datetime | None = None,
    recorded_at: datetime | None = None,
) -> ResearchMemoryRecord:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        handle.seek(0)
        records = _parse_memory(handle.read())
        _verify_records(records)
        if any(record.event_id == event_id for record in records):
            raise MemoryVerificationError(f"duplicate memory event ID: {event_id}")
        if corrects_event_id is not None and not any(
            record.event_id == corrects_event_id for record in records
        ):
            raise MemoryVerificationError("correction must reference an earlier memory event")
        previous = records[-1].event_hash if records else MEMORY_GENESIS_HASH
        occurred = occurred_at or datetime.now(UTC)
        body: dict[str, Any] = {
            "schema_version": "daniel.research-memory.v2",
            "mission_id": "inbar",
            "sequence": len(records),
            "event_id": event_id,
            "occurred_at": occurred,
            "recorded_at": recorded_at or datetime.now(UTC),
            "stage": stage,
            "epistemic_phase": epistemic_phase,
            "actor": actor,
            "event_type": event_type,
            "status": status,
            "summary": summary,
            "payload": payload,
            "evidence": evidence,
            "links": links or {},
            "access": access,
            "source_commit": source_commit,
            "manual_minutes": manual_minutes,
            "cost_usd": cost_usd,
            "recurrence_key": recurrence_key,
            "engine_requirement": engine_requirement,
            "corrects_event_id": corrects_event_id,
            "previous_event_hash": previous,
        }
        record = ResearchMemoryRecord.model_validate(
            {**body, "event_hash": sha256_value(_record_body(body))}
        )
        _verify_records([*records, record])
        handle.seek(0, os.SEEK_END)
        handle.write(canonical_json(record).decode())
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        return record
