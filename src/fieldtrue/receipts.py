"""Signed append-only execution ledger with a locally anchored head."""

from __future__ import annotations

import fcntl
import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Self

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey
from pydantic import BaseModel, ConfigDict, Field, model_validator

from fieldtrue.canonical import (
    atomic_write,
    canonical_json,
    canonical_json_pretty,
    sha256_bytes,
    sha256_value,
)
from fieldtrue.domain import Ed25519PublicKey, HexSignature, Identifier, Sha256
from fieldtrue.runtime import RuntimeIdentity

GENESIS_HASH = "0" * 64


class LedgerVerificationError(ValueError):
    """The ledger, signature chain, or local head is inconsistent."""


class LedgerEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["fieldtrue.ledger-event.v1"] = "fieldtrue.ledger-event.v1"
    sequence: int = Field(ge=0)
    timestamp: datetime
    run_id: Identifier
    event_type: Identifier
    payload: dict[str, Any]
    payload_hash: Sha256
    previous_event_hash: Sha256
    runtime: RuntimeIdentity
    approval_receipt_hash: Sha256 | None = None
    signer_public_key: Ed25519PublicKey
    event_hash: Sha256
    signature: HexSignature

    @model_validator(mode="after")
    def timestamp_is_aware(self) -> Self:
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValueError("ledger timestamp must be timezone-aware")
        return self


class LedgerHead(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["fieldtrue.ledger-head.v1"] = "fieldtrue.ledger-head.v1"
    event_count: int = Field(ge=0)
    head_hash: Sha256
    signer_public_key: Ed25519PublicKey
    signature: HexSignature
    trust_level: Literal["local_ed25519_no_external_timestamp"] = (
        "local_ed25519_no_external_timestamp"
    )


class SignerAnchor(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["fieldtrue.signer-anchor.v1"] = "fieldtrue.signer-anchor.v1"
    anchor_id: Identifier
    mission_id: Literal["fieldtrue"] = "fieldtrue"
    ledger_scope: str = Field(min_length=1)
    signer_public_key: Ed25519PublicKey
    trust_basis: Literal["git-preregistered-local-key"] = "git-preregistered-local-key"


class PublicationSignerAnchor(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["inbar.publication-signer-anchor.v1"] = (
        "inbar.publication-signer-anchor.v1"
    )
    anchor_id: Identifier
    mission_id: Literal["inbar"] = "inbar"
    ledger_scope: str = Field(min_length=1)
    signer_public_key: Ed25519PublicKey
    trust_basis: Literal["git-anchored-inbar-release-key"] = "git-anchored-inbar-release-key"


class LedgerVerification(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_count: int
    head_hash: Sha256
    signer_public_key: Ed25519PublicKey
    trust_level: Literal["git_pinned_ed25519_no_external_timestamp"]


def _public_key(signing_key: SigningKey) -> str:
    return signing_key.verify_key.encode().hex()


def _event_body(event: LedgerEvent | dict[str, Any]) -> dict[str, Any]:
    body = event.model_dump(mode="json") if isinstance(event, LedgerEvent) else dict(event)
    body.pop("event_hash", None)
    body.pop("signature", None)
    return body


def _head_body(head: LedgerHead | dict[str, Any]) -> dict[str, Any]:
    body = head.model_dump(mode="json") if isinstance(head, LedgerHead) else dict(head)
    body.pop("signature", None)
    return body


def load_or_create_signing_key(path: Path) -> SigningKey:
    path.parent.mkdir(parents=True, exist_ok=True)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow,
            0o600,
        )
    except FileExistsError:
        descriptor = os.open(path, os.O_RDONLY | no_follow)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            os.close(descriptor)
            raise PermissionError("signing key must be a regular file") from None
        if metadata.st_uid != os.geteuid():
            os.close(descriptor)
            raise PermissionError("signing key must be owned by the current user") from None
        mode = metadata.st_mode & 0o777
        if mode & 0o077:
            os.close(descriptor)
            raise PermissionError(f"signing key permissions are too broad: {oct(mode)}") from None
        with os.fdopen(descriptor, "rb") as handle:
            data = handle.read()
        if len(data) != 32:
            raise ValueError("signing key must contain exactly 32 seed bytes") from None
        return SigningKey(data)
    key = SigningKey.generate()
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(key.encode())
        handle.flush()
        os.fsync(handle.fileno())
    return key


def write_signer_anchor(
    path: Path,
    signing_key: SigningKey,
    *,
    anchor_id: Identifier,
    ledger_scope: str,
) -> SignerAnchor:
    anchor = SignerAnchor(
        anchor_id=anchor_id,
        ledger_scope=ledger_scope,
        signer_public_key=_public_key(signing_key),
    )
    if path.exists():
        existing = SignerAnchor.model_validate_json(path.read_text(encoding="utf-8"))
        if existing != anchor:
            raise LedgerVerificationError("existing signer anchor does not match local key")
        return existing
    atomic_write(path, canonical_json_pretty(anchor))
    return anchor


def load_signer_anchor(path: Path) -> SignerAnchor:
    if path.is_symlink() or not path.is_file():
        raise LedgerVerificationError("signer anchor must be a committed regular file")
    return SignerAnchor.model_validate_json(path.read_text(encoding="utf-8"))


def write_publication_signer_anchor(
    path: Path,
    signing_key: SigningKey,
    *,
    anchor_id: Identifier,
    ledger_scope: str,
) -> PublicationSignerAnchor:
    anchor = PublicationSignerAnchor(
        anchor_id=anchor_id,
        ledger_scope=ledger_scope,
        signer_public_key=_public_key(signing_key),
    )
    if path.exists():
        existing = PublicationSignerAnchor.model_validate_json(path.read_text(encoding="utf-8"))
        if existing != anchor:
            raise LedgerVerificationError(
                "existing publication signer anchor does not match local key"
            )
        return existing
    atomic_write(path, canonical_json_pretty(anchor))
    return anchor


def load_publication_signer_anchor(path: Path) -> PublicationSignerAnchor:
    if path.is_symlink() or not path.is_file():
        raise LedgerVerificationError("publication signer anchor must be a committed regular file")
    return PublicationSignerAnchor.model_validate_json(path.read_text(encoding="utf-8"))


def _verify_event(event: LedgerEvent, expected_sequence: int, expected_previous: str) -> None:
    if event.sequence != expected_sequence:
        raise LedgerVerificationError(
            f"sequence mismatch: expected {expected_sequence}, got {event.sequence}"
        )
    if event.previous_event_hash != expected_previous:
        raise LedgerVerificationError("previous-event hash mismatch")
    if sha256_value(event.payload) != event.payload_hash:
        raise LedgerVerificationError("payload hash mismatch")
    expected_hash = sha256_value(_event_body(event))
    if expected_hash != event.event_hash:
        raise LedgerVerificationError("event hash mismatch")
    try:
        VerifyKey(bytes.fromhex(event.signer_public_key)).verify(
            bytes.fromhex(event.event_hash), bytes.fromhex(event.signature)
        )
    except (BadSignatureError, ValueError) as error:
        raise LedgerVerificationError("event signature mismatch") from error


def _parse_events(data: str) -> list[LedgerEvent]:
    events: list[LedgerEvent] = []
    for line_number, line in enumerate(data.splitlines(), start=1):
        if not line.strip():
            raise LedgerVerificationError(f"blank ledger line at {line_number}")
        try:
            events.append(LedgerEvent.model_validate_json(line))
        except (ValueError, json.JSONDecodeError) as error:
            raise LedgerVerificationError(f"invalid ledger line {line_number}") from error
    return events


def _verify_events(events: list[LedgerEvent]) -> tuple[str, str]:
    transitions = {
        "run-started": {"sources-verified", "source-invalid", "run-failed"},
        "sources-verified": {"dataset-ingested", "ingestion-invalid", "run-failed"},
        "source-invalid": {"readiness-adjudicated", "run-failed"},
        "ingestion-invalid": {"readiness-adjudicated", "run-failed"},
        "dataset-ingested": {"readiness-adjudicated", "run-failed"},
        "readiness-adjudicated": {"run-completed", "run-failed"},
        "run-completed": set(),
        "run-failed": set(),
    }
    previous = GENESIS_HASH
    signer: str | None = None
    run_id: str | None = None
    runtime: RuntimeIdentity | None = None
    previous_timestamp: datetime | None = None
    seen_types: set[str] = set()
    for sequence, event in enumerate(events):
        _verify_event(event, sequence, previous)
        if signer is None:
            signer = event.signer_public_key
        elif signer != event.signer_public_key:
            raise LedgerVerificationError("signer changed inside one ledger")
        if run_id is None:
            run_id = event.run_id
            runtime = event.runtime
        elif event.run_id != run_id or event.runtime != runtime:
            raise LedgerVerificationError("run ID or runtime changed inside one ledger")
        if previous_timestamp is not None and event.timestamp < previous_timestamp:
            raise LedgerVerificationError("ledger timestamps are not monotonic")
        if sequence == 0:
            if event.event_type != "run-started":
                raise LedgerVerificationError("ledger must begin with run-started")
        else:
            previous_type = events[sequence - 1].event_type
            if event.event_type not in transitions.get(previous_type, set()):
                raise LedgerVerificationError("ledger event violates the iteration lifecycle")
        if event.event_type not in transitions:
            raise LedgerVerificationError("unknown ledger event type")
        if event.event_type in seen_types:
            raise LedgerVerificationError(f"duplicate ledger event type: {event.event_type}")
        if event.event_type == "run-completed" and "readiness-adjudicated" not in seen_types:
            raise LedgerVerificationError("run-completed requires readiness adjudication")
        seen_types.add(event.event_type)
        previous_timestamp = event.timestamp
        previous = event.event_hash
    return previous, signer or sha256_bytes(b"")


def verify_ledger(
    ledger_path: Path,
    head_path: Path,
    *,
    expected_signer_public_key: Ed25519PublicKey,
) -> LedgerVerification:
    if not ledger_path.is_file() or not head_path.is_file():
        raise LedgerVerificationError("ledger and head must both exist")
    events = _parse_events(ledger_path.read_text(encoding="utf-8"))
    if not events:
        raise LedgerVerificationError("ledger must contain at least one event")
    head_hash, signer = _verify_events(events)
    head = LedgerHead.model_validate_json(head_path.read_text(encoding="utf-8"))
    if head.event_count != len(events) or head.head_hash != head_hash:
        raise LedgerVerificationError("local head does not match ledger tail")
    if signer != expected_signer_public_key or head.signer_public_key != expected_signer_public_key:
        raise LedgerVerificationError("ledger signer does not match the pinned trust anchor")
    if events and head.signer_public_key != signer:
        raise LedgerVerificationError("head signer does not match event signer")
    expected_signature_payload = canonical_json(_head_body(head))
    try:
        VerifyKey(bytes.fromhex(head.signer_public_key)).verify(
            expected_signature_payload, bytes.fromhex(head.signature)
        )
    except (BadSignatureError, ValueError) as error:
        raise LedgerVerificationError("head signature mismatch") from error
    return LedgerVerification(
        event_count=len(events),
        head_hash=head_hash,
        signer_public_key=head.signer_public_key,
        trust_level="git_pinned_ed25519_no_external_timestamp",
    )


class SignedLedger:
    def __init__(self, ledger_path: Path, head_path: Path, signing_key: SigningKey) -> None:
        self.ledger_path = ledger_path
        self.head_path = head_path
        self.signing_key = signing_key

    def append(
        self,
        *,
        run_id: Identifier,
        event_type: Identifier,
        payload: dict[str, Any],
        runtime: RuntimeIdentity,
        approval_receipt_hash: Sha256 | None = None,
        timestamp: datetime | None = None,
    ) -> LedgerEvent:
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with self.ledger_path.open("a+", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            handle.seek(0)
            events = _parse_events(handle.read())
            previous, existing_signer = _verify_events(events)
            public_key = _public_key(self.signing_key)
            if events and public_key != existing_signer:
                raise LedgerVerificationError("append signer does not match existing ledger")
            body: dict[str, Any] = {
                "schema_version": "fieldtrue.ledger-event.v1",
                "sequence": len(events),
                "timestamp": timestamp or datetime.now(UTC),
                "run_id": run_id,
                "event_type": event_type,
                "payload": payload,
                "payload_hash": sha256_value(payload),
                "previous_event_hash": previous,
                "runtime": runtime,
                "approval_receipt_hash": approval_receipt_hash,
                "signer_public_key": public_key,
            }
            event_hash = sha256_value(_event_body(body))
            signature = self.signing_key.sign(bytes.fromhex(event_hash)).signature.hex()
            event = LedgerEvent.model_validate(
                {**body, "event_hash": event_hash, "signature": signature}
            )
            _verify_events([*events, event])
            handle.seek(0, os.SEEK_END)
            handle.write(canonical_json(event).decode())
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
            self._write_head(event_count=len(events) + 1, head_hash=event.event_hash)
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            return event

    def _write_head(self, *, event_count: int, head_hash: Sha256) -> None:
        body: dict[str, Any] = {
            "schema_version": "fieldtrue.ledger-head.v1",
            "event_count": event_count,
            "head_hash": head_hash,
            "signer_public_key": _public_key(self.signing_key),
            "trust_level": "local_ed25519_no_external_timestamp",
        }
        signature = self.signing_key.sign(canonical_json(body)).signature.hex()
        head = LedgerHead.model_validate({**body, "signature": signature})
        atomic_write(self.head_path, canonical_json_pretty(head))
