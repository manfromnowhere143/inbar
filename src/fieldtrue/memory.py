"""Append-only extraction memory for the future standalone research engine."""

from __future__ import annotations

import fcntl
import json
import os
import stat
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Self
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from fieldtrue.canonical import canonical_json, sha256_value
from fieldtrue.domain import GitObjectId, Identifier, Sha256

MEMORY_GENESIS_HASH = "0" * 64
_MAX_MEMORY_BYTES = 16 * 1024 * 1024
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
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        json_schema_extra={
            "allOf": [
                {
                    "oneOf": [
                        {
                            "properties": {
                                "uri": {
                                    "type": "string",
                                    "pattern": r"^https://[^/?#]+(?:/|$)",
                                },
                                "sha256": {"type": "string"},
                                "git_commit": {"type": "null"},
                            },
                            "required": ["uri", "sha256"],
                        },
                        {
                            "properties": {
                                "uri": {
                                    "type": "string",
                                    "not": {"pattern": r"^[A-Za-z][A-Za-z0-9+.-]*:"},
                                },
                                "git_commit": {"type": "string"},
                            },
                            "required": ["uri", "git_commit"],
                        },
                    ]
                }
            ]
        },
    )

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
            if "?" in self.uri or "#" in self.uri:
                raise ValueError(
                    "external memory evidence URI must not contain a query or fragment"
                )
            if self.sha256 is None:
                raise ValueError("external memory evidence requires a content hash")
            if self.git_commit is not None:
                raise ValueError("external memory evidence must not include a Git commit")
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


def _memory_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise MemoryVerificationError(f"duplicate memory object key: {key}")
        value[key] = item
    return value


def _reject_memory_constant(value: str) -> Any:
    raise MemoryVerificationError(f"non-finite memory number: {value}")


def _parse_memory(text: str) -> list[ResearchMemoryRecord]:
    if "\r" in text:
        raise MemoryVerificationError("research memory must use exact LF framing")
    if text and not text.endswith("\n"):
        raise MemoryVerificationError("nonempty research memory must end with one LF")
    records: list[ResearchMemoryRecord] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            raise MemoryVerificationError(f"blank memory line at {line_number}")
        try:
            value = json.loads(
                line,
                object_pairs_hook=_memory_object,
                parse_constant=_reject_memory_constant,
            )
            record = ResearchMemoryRecord.model_validate(value)
        except MemoryVerificationError:
            raise
        except ValueError as error:
            raise MemoryVerificationError(f"invalid memory line {line_number}") from error
        if canonical_json(record.model_dump(mode="json")) != line.encode("utf-8"):
            raise MemoryVerificationError(f"noncanonical memory line at {line_number}")
        records.append(record)
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


def _stable_stat_fields(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _memory_file_flags(*, append: bool = False) -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise MemoryVerificationError("research memory requires file no-follow support")
    flags = os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    if append:
        return flags | os.O_RDWR | os.O_APPEND | os.O_CREAT
    return flags | os.O_RDONLY


def _validate_memory_file(metadata: os.stat_result, *, label: str) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise MemoryVerificationError(f"{label} must be a regular file")
    if metadata.st_nlink != 1:
        raise MemoryVerificationError(f"{label} must not be hard linked")
    if metadata.st_size > _MAX_MEMORY_BYTES:
        raise MemoryVerificationError(f"{label} exceeds the memory byte limit")


def _current_memory_file_stat(path: Path, *, label: str) -> os.stat_result:
    try:
        return os.stat(path, follow_symlinks=False)
    except OSError as error:
        raise MemoryVerificationError(f"{label} changed while being read") from error


def _read_memory_file(
    path: Path,
    *,
    missing_ok: bool,
    label: str,
) -> bytes | None:
    try:
        descriptor = os.open(path, _memory_file_flags())
    except FileNotFoundError:
        if missing_ok:
            return None
        raise MemoryVerificationError(f"{label} is missing") from None
    except OSError as error:
        raise MemoryVerificationError(f"{label} is unavailable or is a symbolic link") from error
    try:
        before = os.fstat(descriptor)
        _validate_memory_file(before, label=label)
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = handle.read(_MAX_MEMORY_BYTES + 1)
        after = os.fstat(descriptor)
        current = _current_memory_file_stat(path, label=label)
    finally:
        os.close(descriptor)
    if (
        _stable_stat_fields(before) != _stable_stat_fields(after)
        or _stable_stat_fields(after) != _stable_stat_fields(current)
        or not stat.S_ISREG(current.st_mode)
        or current.st_nlink != 1
        or len(data) != before.st_size
        or len(data) > _MAX_MEMORY_BYTES
    ):
        raise MemoryVerificationError(f"{label} changed while being read")
    return data


def verify_memory(path: Path) -> tuple[int, str]:
    data = _read_memory_file(path, missing_ok=True, label="research memory")
    if data is None:
        return 0, MEMORY_GENESIS_HASH
    records = load_memory_records_bytes(data)
    return len(records), records[-1].event_hash if records else MEMORY_GENESIS_HASH


def load_memory_records(path: Path) -> tuple[ResearchMemoryRecord, ...]:
    data = _read_memory_file(path, missing_ok=True, label="research memory")
    if data is None:
        return ()
    return load_memory_records_bytes(data)


def load_memory_records_bytes(data: bytes) -> tuple[ResearchMemoryRecord, ...]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise MemoryVerificationError("research memory is not valid UTF-8") from error
    records = _parse_memory(text)
    _verify_records(records)
    return tuple(records)


def verify_memory_prefix(base_path: Path, current_path: Path) -> tuple[int, int]:
    base_data = _read_memory_file(base_path, missing_ok=False, label="base memory ledger")
    current_data = _read_memory_file(
        current_path,
        missing_ok=False,
        label="current memory ledger",
    )
    assert base_data is not None
    assert current_data is not None
    base_lines = base_data.splitlines(keepends=True)
    current_lines = current_data.splitlines(keepends=True)
    if current_lines[: len(base_lines)] != base_lines:
        raise MemoryVerificationError("base memory ledger is not an immutable prefix")
    base_records = load_memory_records_bytes(base_data)
    current_records = load_memory_records_bytes(current_data)
    return len(base_records), len(current_records)


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
    try:
        descriptor = os.open(path, _memory_file_flags(append=True), 0o644)
    except OSError as error:
        raise MemoryVerificationError(
            "research memory is unavailable or is a symbolic link"
        ) from error
    with os.fdopen(descriptor, "a+b") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        before = os.fstat(handle.fileno())
        _validate_memory_file(before, label="research memory")
        handle.seek(0)
        existing = handle.read(_MAX_MEMORY_BYTES + 1)
        after_read = os.fstat(handle.fileno())
        current = _current_memory_file_stat(path, label="research memory")
        if (
            _stable_stat_fields(before) != _stable_stat_fields(after_read)
            or _stable_stat_fields(after_read) != _stable_stat_fields(current)
            or not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or len(existing) != before.st_size
            or len(existing) > _MAX_MEMORY_BYTES
        ):
            raise MemoryVerificationError("research memory changed while being read")
        records = list(load_memory_records_bytes(existing))
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
        record_line = canonical_json(record) + b"\n"
        expected_size = before.st_size + len(record_line)
        if expected_size > _MAX_MEMORY_BYTES:
            raise MemoryVerificationError("research memory exceeds the memory byte limit")
        handle.seek(0, os.SEEK_END)
        if handle.write(record_line) != len(record_line):
            raise MemoryVerificationError("research memory append was incomplete")
        handle.flush()
        os.fsync(handle.fileno())
        final = os.fstat(handle.fileno())
        final_current = _current_memory_file_stat(path, label="research memory")
        final_identity = (
            final.st_dev,
            final.st_ino,
            final.st_mode,
            final.st_nlink,
            final.st_uid,
            final.st_gid,
        )
        current_identity = (
            final_current.st_dev,
            final_current.st_ino,
            final_current.st_mode,
            final_current.st_nlink,
            final_current.st_uid,
            final_current.st_gid,
        )
        if (
            final_identity != current_identity
            or not stat.S_ISREG(final_current.st_mode)
            or final_current.st_nlink != 1
            or final.st_size != expected_size
            or final_current.st_size != expected_size
        ):
            raise MemoryVerificationError("research memory changed while being appended")
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        return record
