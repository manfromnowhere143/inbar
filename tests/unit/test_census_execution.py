"""Adversarial controls for census execution: lease, transport, ceiling, frame, store.

Amendment 003 requires these controls to run without live network access, so every session
here uses an injected transport. A lease that could widen its ceiling, a session that could
retrieve outside the frame, past a failing gate, or beyond the byte ceiling, or a store that
could be replayed, would each reopen exactly the discipline the census imposes on its sources.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from nacl.signing import SigningKey
from pydantic import ValidationError

from fieldtrue.canonical import sha256_value
from fieldtrue.census_execution import (
    AMENDMENT_DOCUMENT_SHA256,
    APPROVED_PROPOSAL_COMMIT,
    FRAME_REGISTRY_PATH,
    MACHINE_PROPOSAL_SHA256,
    OWNER_APPROVAL_RECEIPT_HASH,
    CensusExecutionError,
    CensusExecutionLease,
    CensusSession,
    FrameRegistry,
    census_lease_body,
    issue_census_lease,
    verify_census_lease,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
KEY = SigningKey((REPO_ROOT / ".local/keys/iter001-governance.ed25519").read_bytes())
REGISTRY_BYTES = (REPO_ROOT / FRAME_REGISTRY_PATH).read_bytes()
REGISTRY_HASH = hashlib.sha256(REGISTRY_BYTES).hexdigest()
NOW = datetime(2026, 7, 17, 12, 0, 0, tzinfo=UTC)
ALLOWED_URI = "https://data.ntsb.gov/carol-main-public/basic-search"


def _lease(session_id: str = "sess-1", **overrides: object) -> CensusExecutionLease:
    lease = issue_census_lease(
        KEY,
        lease_id="lease-1",
        session_id=session_id,
        frame_registry_artifact_sha256=REGISTRY_HASH,
        not_before=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(hours=1),
        nonce="a" * 64,
    )
    if overrides:
        body = {
            k: v
            for k, v in lease.model_dump(mode="json").items()
            if k not in ("lease_hash", "signature")
        }
        body.update(overrides)
        forged_hash = sha256_value(body)
        signature = KEY.sign(bytes.fromhex(forged_hash)).signature.hex()
        return CensusExecutionLease.model_validate(
            {**body, "lease_hash": forged_hash, "signature": signature}
        )
    return lease


def _ok_transport(uri: str) -> tuple[int, str, tuple[str, ...], bytes]:
    return 200, uri, (), b"<html>docket</html>"


def _session(lease: CensusExecutionLease, transport=_ok_transport, now=None) -> CensusSession:
    return CensusSession(REPO_ROOT, lease, transport=transport, now=now or (lambda: NOW))


def _purge_store() -> None:
    import shutil

    store = REPO_ROOT / ".local/census"
    for pattern in ("sess-*", "dup-*"):
        for child in store.glob(pattern):
            shutil.rmtree(child, ignore_errors=True)


@pytest.fixture(autouse=True)
def _clean_store() -> object:
    # Purge at BOTH setup and teardown: an interrupted run leaves a session directory on disk
    # whose one-lease-one-session guard would otherwise poison the next run with a spurious
    # "session store already exists". Setup-purge makes the suite robust to that residue.
    _purge_store()
    yield
    _purge_store()


# --- Lease controls ----------------------------------------------------------------


def test_committed_lease_issues_and_verifies() -> None:
    lease = _lease()
    verify_census_lease(lease, frame_registry_bytes=REGISTRY_BYTES, at=NOW)
    assert lease.owner_approval_receipt_hash == OWNER_APPROVAL_RECEIPT_HASH
    assert lease.proposal_git_commit == APPROVED_PROPOSAL_COMMIT
    assert lease.amendment_document_artifact_sha256 == AMENDMENT_DOCUMENT_SHA256
    assert lease.machine_proposal_artifact_sha256 == MACHINE_PROPOSAL_SHA256


def test_a_widened_ceiling_fails_closed() -> None:
    lease = _lease(max_retrieved_bytes=1024**4)
    with pytest.raises(CensusExecutionError, match="ceiling differs from the frozen"):
        verify_census_lease(lease, frame_registry_bytes=REGISTRY_BYTES, at=NOW)


def test_a_wrong_frame_registry_fails_closed() -> None:
    lease = _lease()
    with pytest.raises(CensusExecutionError, match="does not bind the committed frame registry"):
        verify_census_lease(lease, frame_registry_bytes=REGISTRY_BYTES + b" ", at=NOW)


def test_a_scope_forgery_fails_closed() -> None:
    lease = _lease(owner_approval_receipt_hash="e" * 64)
    with pytest.raises(CensusExecutionError, match="approved execution scope"):
        verify_census_lease(lease, frame_registry_bytes=REGISTRY_BYTES, at=NOW)


def test_an_expired_lease_fails_closed() -> None:
    lease = _lease()
    with pytest.raises(CensusExecutionError, match="not currently valid"):
        verify_census_lease(lease, frame_registry_bytes=REGISTRY_BYTES, at=NOW + timedelta(days=2))


def test_a_forged_signature_fails_closed() -> None:
    lease = _lease()
    forged = lease.model_copy(update={"signature": "a" * 128})
    with pytest.raises(CensusExecutionError, match="signature mismatch"):
        verify_census_lease(forged, frame_registry_bytes=REGISTRY_BYTES, at=NOW)


def test_lease_hash_forgery_is_rejected_by_the_model() -> None:
    lease = _lease()
    body = census_lease_body(lease)
    body["nonce"] = "f" * 64
    with pytest.raises(ValidationError, match="lease hash mismatch"):
        CensusExecutionLease.model_validate(
            {**body, "lease_hash": lease.lease_hash, "signature": lease.signature}
        )


def test_naive_lease_window_is_rejected() -> None:
    with pytest.raises(ValidationError):
        issue_census_lease(
            KEY,
            lease_id="lease-x",
            session_id="sess-x",
            frame_registry_artifact_sha256=REGISTRY_HASH,
            not_before=datetime(2026, 7, 17, 12, 0, 0),  # noqa: DTZ001
            expires_at=NOW + timedelta(hours=1),
            nonce="a" * 64,
        )


# --- Session and transport controls ------------------------------------------------


def test_session_refuses_to_construct_on_an_invalid_lease() -> None:
    lease = _lease(max_cpu_seconds=1.0)
    with pytest.raises(CensusExecutionError, match="ceiling differs"):
        _session(lease)


def test_retrieval_outside_the_frame_is_refused() -> None:
    session = _session(_lease())
    with pytest.raises(CensusExecutionError, match="outside the committed frame registry"):
        session.retrieve("cand-1", "https://evil.example.com/x")


def test_non_https_retrieval_is_refused() -> None:
    session = _session(_lease())
    with pytest.raises(CensusExecutionError, match="https-only"):
        session.retrieve("cand-1", "http://data.ntsb.gov/x")


def test_retrieval_past_a_failing_gate_is_refused() -> None:
    session = _session(_lease())
    session.record_failed_gate("cand-1")
    with pytest.raises(CensusExecutionError, match="stop rule forbids retrieval"):
        session.retrieve("cand-1", ALLOWED_URI)


def test_retrieval_beyond_the_byte_ceiling_is_refused() -> None:
    # A lease cannot legally carry a widened ceiling, so the runtime cap is exercised with a
    # transport whose single response exceeds the frozen budget. Only its length matters here,
    # so a sparse in-memory buffer stands in for the multi-gigabyte body.
    lease = _lease()

    class _OversizeBody(bytes):
        def __len__(self) -> int:  # type: ignore[override]
            return lease.max_retrieved_bytes + 1

    session = _session(lease, transport=lambda uri: (200, uri, (), _OversizeBody(b"x")))
    with pytest.raises(CensusExecutionError, match="frozen byte ceiling"):
        session.retrieve("cand-1", ALLOWED_URI)


def test_a_non_200_status_is_refused() -> None:
    session = _session(_lease(), transport=lambda uri: (404, uri, (), b""))
    with pytest.raises(CensusExecutionError, match="status 404"):
        session.retrieve("cand-1", ALLOWED_URI)


def test_excess_redirects_are_refused() -> None:
    hops = tuple(f"https://data.ntsb.gov/{i}" for i in range(7))
    session = _session(_lease(), transport=lambda uri: (200, uri, hops, b"x"))
    with pytest.raises(CensusExecutionError, match="redirect depth exceeded"):
        session.retrieve("cand-1", ALLOWED_URI)


def test_a_successful_retrieval_is_recorded_and_content_addressed() -> None:
    session = _session(_lease())
    record = session.retrieve("cand-1", ALLOWED_URI)
    assert record.response_sha256 == hashlib.sha256(b"<html>docket</html>").hexdigest()
    assert record.final_uri == ALLOWED_URI
    blob = REPO_ROOT / ".local/census/sess-1/blobs" / record.response_sha256
    assert blob.read_bytes() == b"<html>docket</html>"
    manifest = (REPO_ROOT / ".local/census/sess-1/manifest.jsonl").read_text().splitlines()
    assert json.loads(manifest[0])["candidate_id"] == "cand-1"
    binding = session.execution_binding()
    assert binding.retrieval_count == 1
    assert binding.retrieved_bytes == len(b"<html>docket</html>")
    assert binding.lease_hash == session._lease.lease_hash


def test_a_replayed_session_id_is_refused() -> None:
    lease = _lease(session_id="dup-1")
    _session(lease)
    replay = issue_census_lease(
        KEY,
        lease_id="lease-2",
        session_id="dup-1",
        frame_registry_artifact_sha256=REGISTRY_HASH,
        not_before=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(hours=1),
        nonce="b" * 64,
    )
    with pytest.raises(CensusExecutionError, match="session store already exists"):
        _session(replay)


# --- Frame registry controls -------------------------------------------------------


def test_committed_frame_registry_names_the_nine_frozen_domains() -> None:
    registry = FrameRegistry.model_validate_json(REGISTRY_BYTES)
    assert len(registry.entries) == 9
    from fieldtrue.census import STRATUM_B_DOMAINS

    assert {entry.domain_id for entry in registry.entries} == set(STRATUM_B_DOMAINS)


def test_frame_registry_entry_points_must_be_https() -> None:
    from fieldtrue.census_execution import FrameRegistryEntry

    with pytest.raises(ValidationError, match="https"):
        FrameRegistryEntry(
            domain_id="d",
            enumeration_method="m",
            entry_points=("http://insecure.example.com/",),
        )


# --- Production transport controls (urlopen stubbed; no live network) ---------------


class _FakeResponse:
    def __init__(self, status: int, headers: dict[str, str], body: bytes) -> None:
        self.status = status
        self.headers = headers
        self._body = body

    def read(self, _limit: int) -> bytes:
        return self._body

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None


def test_transport_returns_status_final_uri_and_body(monkeypatch: pytest.MonkeyPatch) -> None:
    from fieldtrue import census_execution

    monkeypatch.setattr(
        census_execution.urllib.request,
        "urlopen",
        lambda *_a, **_k: _FakeResponse(200, {}, b"payload"),
    )
    status, final_uri, hops, body = census_execution.https_certifi_transport(ALLOWED_URI)
    assert status == 200
    assert final_uri == ALLOWED_URI
    assert hops == ()
    assert body == b"payload"


def test_transport_follows_a_bounded_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    from fieldtrue import census_execution

    calls = {"n": 0}

    def fake_urlopen(request: object, *_a: object, **_k: object) -> _FakeResponse:
        calls["n"] += 1
        if calls["n"] == 1:
            return _FakeResponse(302, {"Location": "https://data.ntsb.gov/moved"}, b"")
        return _FakeResponse(200, {}, b"final")

    monkeypatch.setattr(census_execution.urllib.request, "urlopen", fake_urlopen)
    status, final_uri, hops, body = census_execution.https_certifi_transport(ALLOWED_URI)
    assert status == 200
    assert final_uri == "https://data.ntsb.gov/moved"
    assert hops == (ALLOWED_URI,)
    assert body == b"final"


def test_transport_refuses_a_redirect_without_a_location(monkeypatch: pytest.MonkeyPatch) -> None:
    from fieldtrue import census_execution

    monkeypatch.setattr(
        census_execution.urllib.request,
        "urlopen",
        lambda *_a, **_k: _FakeResponse(302, {}, b""),
    )
    with pytest.raises(CensusExecutionError, match="redirect without a location"):
        census_execution.https_certifi_transport(ALLOWED_URI)


def test_transport_refuses_a_downgraded_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    from fieldtrue import census_execution

    monkeypatch.setattr(
        census_execution.urllib.request,
        "urlopen",
        lambda *_a, **_k: _FakeResponse(302, {"Location": "http://data.ntsb.gov/x"}, b""),
    )
    with pytest.raises(CensusExecutionError, match="https-only"):
        census_execution.https_certifi_transport(ALLOWED_URI)


def test_transport_wraps_a_url_error(monkeypatch: pytest.MonkeyPatch) -> None:
    from fieldtrue import census_execution

    def raiser(*_a: object, **_k: object) -> object:
        raise census_execution.urllib.error.URLError("boom")

    monkeypatch.setattr(census_execution.urllib.request, "urlopen", raiser)
    with pytest.raises(CensusExecutionError, match="retrieval failed"):
        census_execution.https_certifi_transport(ALLOWED_URI)


def test_transport_refuses_endless_redirects(monkeypatch: pytest.MonkeyPatch) -> None:
    from fieldtrue import census_execution

    monkeypatch.setattr(
        census_execution.urllib.request,
        "urlopen",
        lambda *_a, **_k: _FakeResponse(302, {"Location": "https://data.ntsb.gov/loop"}, b""),
    )
    with pytest.raises(CensusExecutionError, match="redirect depth exceeded"):
        census_execution.https_certifi_transport(ALLOWED_URI)


def test_write_census_lease_emits_canonical_bytes(tmp_path: Path) -> None:
    from fieldtrue.canonical import canonical_json_pretty
    from fieldtrue.census_execution import write_census_lease

    lease = _lease(session_id="sess-write")
    path = write_census_lease(tmp_path, lease, "protocol/approvals/census_lease.json")
    raw = path.read_bytes()
    assert raw == canonical_json_pretty(lease.model_dump(mode="json"))


# --- Remaining guard controls ------------------------------------------------------


def test_duplicate_domains_in_a_frame_registry_are_rejected() -> None:
    from fieldtrue.census_execution import FrameRegistryEntry

    entry = FrameRegistryEntry(
        domain_id="d", enumeration_method="m", entry_points=("https://a.example.com/",)
    )
    with pytest.raises(ValidationError, match="domains must be unique"):
        FrameRegistry(entries=(entry, entry))


def test_a_backwards_lease_window_is_rejected() -> None:
    with pytest.raises(ValidationError, match="expiry must follow"):
        issue_census_lease(
            KEY,
            lease_id="lease-b",
            session_id="sess-b",
            frame_registry_artifact_sha256=REGISTRY_HASH,
            not_before=NOW + timedelta(hours=2),
            expires_at=NOW,
            nonce="a" * 64,
        )


def test_naive_verification_time_is_rejected() -> None:
    with pytest.raises(CensusExecutionError, match="verification time must be timezone-aware"):
        verify_census_lease(
            _lease(),
            frame_registry_bytes=REGISTRY_BYTES,
            at=datetime(2026, 7, 17, 12, 0, 0),  # noqa: DTZ001
        )


def test_naive_retrieval_record_time_is_rejected() -> None:
    from fieldtrue.census_execution import RetrievalRecord

    with pytest.raises(ValidationError, match="retrieval time must be timezone-aware"):
        RetrievalRecord(
            session_id="s",
            candidate_id="c",
            request_uri="https://a/x",
            final_uri="https://a/x",
            redirect_hops=(),
            retrieved_at=datetime(2026, 7, 17, 12, 0, 0),  # noqa: DTZ001
            response_bytes=1,
            response_sha256="a" * 64,
        )


def test_retrieval_after_expiry_is_refused_inside_the_session() -> None:
    # The lease verifies at construction time, then the wall clock advances past expiry; the
    # per-retrieval window recheck must refuse rather than trust the construction-time result.
    clock = {"t": NOW}
    session = _session(_lease(), now=lambda: clock["t"])
    clock["t"] = NOW + timedelta(days=2)
    with pytest.raises(CensusExecutionError, match="not currently valid"):
        session.retrieve("cand-1", ALLOWED_URI)


def test_the_default_clock_is_utc_aware() -> None:
    from fieldtrue.census_execution import _utc_now

    assert _utc_now().tzinfo is not None


def test_a_repeated_blob_is_not_rewritten() -> None:
    session = _session(_lease())
    first = session.retrieve("cand-1", ALLOWED_URI)
    second = session.retrieve("cand-2", ALLOWED_URI)
    assert first.response_sha256 == second.response_sha256
    blob = REPO_ROOT / ".local/census/sess-1/blobs" / first.response_sha256
    assert blob.read_bytes() == b"<html>docket</html>"
