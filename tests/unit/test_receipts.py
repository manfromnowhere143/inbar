from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from fieldtrue.canonical import canonical_json
from fieldtrue.receipts import (
    LedgerVerificationError,
    SignedLedger,
    load_or_create_signing_key,
    load_signer_anchor,
    verify_ledger,
    write_signer_anchor,
)
from tests.helpers import legacy_runtime_identity, runtime_identity


def _ledger(tmp_path: Path) -> tuple[SignedLedger, Path, Path, SigningKey]:
    ledger_path = tmp_path / "events.jsonl"
    head_path = tmp_path / "events.head.json"
    key = SigningKey.generate()
    return SignedLedger(ledger_path, head_path, key), ledger_path, head_path, key


def _verify(path: Path, head: Path, key: SigningKey):
    return verify_ledger(
        path,
        head,
        expected_signer_public_key=key.verify_key.encode().hex(),
    )


def test_signed_ledger_round_trip_and_local_head(tmp_path: Path) -> None:
    ledger, path, head, key = _ledger(tmp_path)
    first = ledger.append(
        run_id="run-1",
        event_type="run-started",
        payload={"stage": "test"},
        runtime=runtime_identity(),
    )
    events = [first]
    for event_type in (
        "sources-verified",
        "dataset-ingested",
        "readiness-adjudicated",
        "run-completed",
    ):
        events.append(
            ledger.append(
                run_id="run-1",
                event_type=event_type,
                payload={"stage": event_type},
                runtime=runtime_identity(),
            )
        )
    verification = _verify(path, head, key)
    assert first.sequence == 0
    assert events[1].previous_event_hash == first.event_hash
    assert verification.event_count == 5
    assert verification.head_hash == events[-1].event_hash
    assert verification.trust_level == "git_pinned_ed25519_no_external_timestamp"


def test_signed_ledger_refuses_legacy_runtime_for_new_events(tmp_path: Path) -> None:
    ledger, path, head, _ = _ledger(tmp_path)
    legacy = legacy_runtime_identity()
    promoted = legacy.model_copy(update={"provenance_state": "observed-v1"})

    for candidate in (legacy, promoted):
        with pytest.raises(LedgerVerificationError, match="require observed-v1"):
            ledger.append(
                run_id="run-legacy",
                event_type="run-started",
                payload={},
                runtime=candidate,
            )

    assert not path.exists()
    assert not head.exists()


def test_payload_tampering_is_detected(tmp_path: Path) -> None:
    ledger, path, head, key = _ledger(tmp_path)
    ledger.append(
        run_id="run-1",
        event_type="run-started",
        payload={"value": 1},
        runtime=runtime_identity(),
    )
    raw = json.loads(path.read_text())
    raw["payload"]["value"] = 2
    path.write_bytes(canonical_json(raw) + b"\n")
    with pytest.raises(LedgerVerificationError, match="payload hash"):
        _verify(path, head, key)


def test_tail_truncation_is_detected_by_head(tmp_path: Path) -> None:
    ledger, path, head, key = _ledger(tmp_path)
    for event_type in ("run-started", "sources-verified"):
        ledger.append(
            run_id="run-1",
            event_type=event_type,
            payload={},
            runtime=runtime_identity(),
        )
    path.write_text(path.read_text().splitlines()[0] + "\n")
    with pytest.raises(LedgerVerificationError, match="head"):
        _verify(path, head, key)


def test_append_with_different_signer_is_rejected(tmp_path: Path) -> None:
    ledger, path, head, _ = _ledger(tmp_path)
    ledger.append(
        run_id="run-1",
        event_type="run-started",
        payload={},
        runtime=runtime_identity(),
    )
    attacker = SignedLedger(path, head, SigningKey.generate())
    with pytest.raises(LedgerVerificationError, match="signer"):
        attacker.append(
            run_id="run-1",
            event_type="sources-verified",
            payload={},
            runtime=runtime_identity(),
        )


def test_local_signing_key_has_private_permissions(tmp_path: Path) -> None:
    key_path = tmp_path / "key.seed"
    first = load_or_create_signing_key(key_path)
    second = load_or_create_signing_key(key_path)
    assert first.encode() == second.encode()
    assert key_path.stat().st_mode & 0o777 == 0o600
    os.chmod(key_path, 0o644)
    with pytest.raises(PermissionError, match="permissions"):
        load_or_create_signing_key(key_path)


def test_missing_or_malformed_ledger_fails_closed(tmp_path: Path) -> None:
    key = SigningKey.generate()
    with pytest.raises(LedgerVerificationError, match="both exist"):
        _verify(tmp_path / "missing", tmp_path / "head", key)
    ledger, path, head, key = _ledger(tmp_path)
    ledger.append(
        run_id="run-1",
        event_type="run-started",
        payload={},
        runtime=runtime_identity(),
    )
    path.write_text("\n")
    with pytest.raises(LedgerVerificationError, match="blank"):
        _verify(path, head, key)


def test_wholesale_replacement_fails_against_the_pinned_signer(tmp_path: Path) -> None:
    _, _, _, trusted_key = _ledger(tmp_path / "trusted")
    attacker, path, head, _ = _ledger(tmp_path / "attacker")
    attacker.append(
        run_id="run-1",
        event_type="run-started",
        payload={},
        runtime=runtime_identity(),
    )
    attacker.append(
        run_id="run-1",
        event_type="run-failed",
        payload={},
        runtime=runtime_identity(),
    )
    with pytest.raises(LedgerVerificationError, match="pinned trust anchor"):
        _verify(path, head, trusted_key)


def test_ledger_enforces_run_runtime_time_and_lifecycle(tmp_path: Path) -> None:
    ledger, _, _, _ = _ledger(tmp_path)
    now = datetime(2026, 7, 14, tzinfo=UTC)
    ledger.append(
        run_id="run-1",
        event_type="run-started",
        payload={},
        runtime=runtime_identity(),
        timestamp=now,
    )
    with pytest.raises(LedgerVerificationError, match="lifecycle"):
        ledger.append(
            run_id="run-1",
            event_type="dataset-ingested",
            payload={},
            runtime=runtime_identity(),
        )
    with pytest.raises(LedgerVerificationError, match="run ID or runtime"):
        ledger.append(
            run_id="different-run",
            event_type="sources-verified",
            payload={},
            runtime=runtime_identity(),
        )
    with pytest.raises(LedgerVerificationError, match="run ID or runtime"):
        ledger.append(
            run_id="run-1",
            event_type="sources-verified",
            payload={},
            runtime=runtime_identity(dirty=True),
        )
    with pytest.raises(LedgerVerificationError, match="monotonic"):
        ledger.append(
            run_id="run-1",
            event_type="sources-verified",
            payload={},
            runtime=runtime_identity(),
            timestamp=now - timedelta(seconds=1),
        )


def test_signing_key_and_anchor_reject_symlink_permissions_and_mismatch(
    tmp_path: Path,
) -> None:
    key_path = tmp_path / "key"
    key = load_or_create_signing_key(key_path)
    anchor_path = tmp_path / "anchor.json"
    anchor = write_signer_anchor(
        anchor_path,
        key,
        anchor_id="anchor-1",
        ledger_scope="fixture",
    )
    assert load_signer_anchor(anchor_path) == anchor
    assert (
        write_signer_anchor(
            anchor_path,
            key,
            anchor_id="anchor-1",
            ledger_scope="fixture",
        )
        == anchor
    )
    with pytest.raises(LedgerVerificationError, match="does not match"):
        write_signer_anchor(
            anchor_path,
            SigningKey.generate(),
            anchor_id="anchor-1",
            ledger_scope="fixture",
        )

    symlink = tmp_path / "key-link"
    os.symlink(key_path, symlink)
    with pytest.raises(OSError, match=r"Too many levels|symbolic link"):
        load_or_create_signing_key(symlink)
    malformed = tmp_path / "malformed"
    malformed.write_bytes(b"short")
    os.chmod(malformed, 0o600)
    with pytest.raises(ValueError, match="32 seed bytes"):
        load_or_create_signing_key(malformed)
    with pytest.raises(LedgerVerificationError, match="regular file"):
        load_signer_anchor(tmp_path / "missing-anchor")


@pytest.mark.parametrize(
    "event_types",
    [
        ("run-started", "source-invalid", "readiness-adjudicated", "run-completed"),
        (
            "run-started",
            "sources-verified",
            "ingestion-invalid",
            "readiness-adjudicated",
            "run-completed",
        ),
    ],
)
def test_ledger_accepts_preregistered_invalid_lifecycles(
    tmp_path: Path,
    event_types: tuple[str, ...],
) -> None:
    ledger, path, head, key = _ledger(tmp_path)
    for event_type in event_types:
        ledger.append(
            run_id="run-1",
            event_type=event_type,
            payload={"stage": event_type},
            runtime=runtime_identity(),
        )
    assert _verify(path, head, key).event_count == len(event_types)
