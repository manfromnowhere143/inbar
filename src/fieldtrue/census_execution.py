"""Census execution: the lease, the retrieval executor, and the session store.

Authorized by owner-approval receipt `iter001-census-execution-owner-approval-003`
(`approve_census_execution_implementation_only`) over Amendment 003 at proposal commit
`7cbd3ad6aff0607552aa0cef270251b56126358f`.

These primitives authorize implementation only. A live census run requires a per-session
execution lease signed by the owner governance key; a missing, expired, replayed,
wrong-frame, wrong-ceiling, or signature-invalid lease blocks retrieval before any network
contact. Third-party bytes are never committed: they live content-addressed in the
git-ignored local census store, and only hashes, counts, and locators reach the repository.
"""

from __future__ import annotations

import hashlib
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Literal, Self

import certifi
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey
from pydantic import Field, model_validator

from fieldtrue.canonical import canonical_json_pretty, sha256_value
from fieldtrue.census import (
    CEILING_CPU_SECONDS,
    CEILING_PEAK_MEMORY_BYTES,
    CEILING_PEAK_STAGED_BYTES,
    CEILING_RETRIEVED_BYTES,
    CEILING_WALL_SECONDS,
    CensusError,
)
from fieldtrue.domain import (
    Ed25519PublicKey,
    FrozenModel,
    GitObjectId,
    HexSignature,
    Identifier,
    Sha256,
)
from fieldtrue.shortcut_contracts import OWNER_PUBLIC_KEY

AMENDMENT_ID: Final = "iter001_003"
APPROVED_PROPOSAL_COMMIT: Final = "7cbd3ad6aff0607552aa0cef270251b56126358f"
AMENDMENT_DOCUMENT_SHA256: Final = (
    "df7a4eaba26b8099b0cf950d01cf1b853c65d44b5c9ff990e71593fdd5c41d72"
)
MACHINE_PROPOSAL_SHA256: Final = "ad487087ed8905773839cbc9259fd26c5f92a4eda676cb4d5ec96593caa8e120"
OWNER_APPROVAL_RECEIPT_HASH: Final = (
    "2c0001fbb952ae1bff5d8b0fe0f7a04eeff7d2fd556a83006c42ae17428f7ec5"
)
FRAME_REGISTRY_PATH: Final = "protocol/census/frame_registry.json"
LOCAL_STORE_ROOT: Final = ".local/census"
MAX_REDIRECT_HOPS: Final = 5
_MAX_SINGLE_RESPONSE_BYTES: Final = 256 * 1024 * 1024


class CensusExecutionError(CensusError):
    """A lease, transport, ceiling, frame, or storage rule refused the operation."""


class FrameRegistryEntry(FrozenModel):
    domain_id: Identifier
    enumeration_method: str = Field(min_length=1)
    entry_points: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def entry_points_are_https(self) -> Self:
        for uri in self.entry_points:
            if urllib.parse.urlsplit(uri).scheme != "https":
                raise ValueError("frame registry entry points must be https")
        return self


class FrameRegistry(FrozenModel):
    schema_version: Literal["inbar.iter001.census-frame-registry.v1"] = (
        "inbar.iter001.census-frame-registry.v1"
    )
    amendment_id: Literal["iter001_003"] = "iter001_003"
    entries: tuple[FrameRegistryEntry, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def domains_are_unique(self) -> Self:
        domains = [entry.domain_id for entry in self.entries]
        if len(set(domains)) != len(domains):
            raise ValueError("frame registry domains must be unique")
        return self

    def allowed_hosts(self) -> frozenset[str]:
        hosts = set()
        for entry in self.entries:
            for uri in entry.entry_points:
                hosts.add(urllib.parse.urlsplit(uri).hostname or "")
        hosts.discard("")
        return frozenset(hosts)


class CensusExecutionLease(FrozenModel):
    """One lease, one session. Every field the machine proposal freezes is bound here."""

    schema_version: Literal["inbar.iter001.census-execution-lease.v1"] = (
        "inbar.iter001.census-execution-lease.v1"
    )
    lease_id: Identifier
    session_id: Identifier
    amendment_document_artifact_sha256: Sha256
    machine_proposal_artifact_sha256: Sha256
    owner_approval_receipt_hash: Sha256
    frame_registry_artifact_sha256: Sha256
    max_cpu_seconds: float = Field(gt=0)
    max_wall_seconds: float = Field(gt=0)
    max_peak_memory_bytes: int = Field(gt=0)
    max_retrieved_bytes: int = Field(gt=0)
    max_peak_staged_bytes: int = Field(gt=0)
    not_before: datetime
    expires_at: datetime
    nonce: Sha256
    owner_ed25519_public_key: Ed25519PublicKey
    proposal_git_commit: GitObjectId
    lease_hash: Sha256
    signature: HexSignature

    @model_validator(mode="after")
    def window_is_well_formed(self) -> Self:
        for value in (self.not_before, self.expires_at):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("lease timestamps must be timezone-aware")
        if self.expires_at <= self.not_before:
            raise ValueError("lease expiry must follow its start")
        return self

    @model_validator(mode="after")
    def lease_hash_is_derived(self) -> Self:
        if sha256_value(census_lease_body(self)) != self.lease_hash:
            raise ValueError("lease hash mismatch")
        return self


def census_lease_body(lease: CensusExecutionLease | dict[str, Any]) -> dict[str, Any]:
    body = lease.model_dump(mode="json") if isinstance(lease, CensusExecutionLease) else dict(lease)
    body.pop("lease_hash", None)
    body.pop("signature", None)
    return body


def issue_census_lease(
    signing_key: SigningKey,
    *,
    lease_id: Identifier,
    session_id: Identifier,
    frame_registry_artifact_sha256: Sha256,
    not_before: datetime,
    expires_at: datetime,
    nonce: Sha256,
) -> CensusExecutionLease:
    """Owner ceremony: sign one session's authority under the frozen ceiling.

    The ceiling values are not parameters. A lease can only restate Amendment 002's frozen
    ceiling, so no ceremony can quietly widen a run.
    """
    body: dict[str, Any] = {
        "schema_version": "inbar.iter001.census-execution-lease.v1",
        "lease_id": lease_id,
        "session_id": session_id,
        "amendment_document_artifact_sha256": AMENDMENT_DOCUMENT_SHA256,
        "machine_proposal_artifact_sha256": MACHINE_PROPOSAL_SHA256,
        "owner_approval_receipt_hash": OWNER_APPROVAL_RECEIPT_HASH,
        "frame_registry_artifact_sha256": frame_registry_artifact_sha256,
        "max_cpu_seconds": CEILING_CPU_SECONDS,
        "max_wall_seconds": CEILING_WALL_SECONDS,
        "max_peak_memory_bytes": CEILING_PEAK_MEMORY_BYTES,
        "max_retrieved_bytes": CEILING_RETRIEVED_BYTES,
        "max_peak_staged_bytes": CEILING_PEAK_STAGED_BYTES,
        "not_before": not_before,
        "expires_at": expires_at,
        "nonce": nonce,
        "owner_ed25519_public_key": signing_key.verify_key.encode().hex(),
        "proposal_git_commit": APPROVED_PROPOSAL_COMMIT,
    }
    normalized = json.loads(
        CensusExecutionLease.model_construct(**body).model_dump_json(
            exclude={"lease_hash", "signature"}
        )
    )
    lease_hash = sha256_value(normalized)
    signature = signing_key.sign(bytes.fromhex(lease_hash)).signature.hex()
    return CensusExecutionLease.model_validate(
        {**normalized, "lease_hash": lease_hash, "signature": signature}
    )


def verify_census_lease(
    lease: CensusExecutionLease,
    *,
    frame_registry_bytes: bytes,
    expected_public_key: Ed25519PublicKey = OWNER_PUBLIC_KEY,
    at: datetime | None = None,
) -> None:
    """Fail closed on any scope, chain, registry, ceiling, window, or signature mismatch.

    `expected_public_key` pins the signer and defaults to the frozen owner key, so a real run
    only accepts an owner-signed lease. It is a parameter, not a constant, for the same reason
    :func:`fieldtrue.approvals.verify_approval` takes its expected signer: a test signs with a
    deterministic key rather than the local-only governance key, which is never on CI.
    """
    checked_at = at or datetime.now(UTC)
    if checked_at.tzinfo is None or checked_at.utcoffset() is None:
        raise CensusExecutionError("lease verification time must be timezone-aware")
    expected = {
        "amendment_document_artifact_sha256": AMENDMENT_DOCUMENT_SHA256,
        "machine_proposal_artifact_sha256": MACHINE_PROPOSAL_SHA256,
        "owner_approval_receipt_hash": OWNER_APPROVAL_RECEIPT_HASH,
        "owner_ed25519_public_key": expected_public_key,
        "proposal_git_commit": APPROVED_PROPOSAL_COMMIT,
    }
    observed = lease.model_dump(mode="json")
    if any(observed[field] != value for field, value in expected.items()):
        raise CensusExecutionError("lease differs from the approved execution scope")
    if lease.frame_registry_artifact_sha256 != hashlib.sha256(frame_registry_bytes).hexdigest():
        raise CensusExecutionError("lease does not bind the committed frame registry")
    ceiling = {
        "max_cpu_seconds": CEILING_CPU_SECONDS,
        "max_wall_seconds": CEILING_WALL_SECONDS,
        "max_peak_memory_bytes": CEILING_PEAK_MEMORY_BYTES,
        "max_retrieved_bytes": CEILING_RETRIEVED_BYTES,
        "max_peak_staged_bytes": CEILING_PEAK_STAGED_BYTES,
    }
    if any(observed[field] != value for field, value in ceiling.items()):
        raise CensusExecutionError("lease ceiling differs from the frozen resource ceiling")
    if not lease.not_before <= checked_at < lease.expires_at:
        raise CensusExecutionError("lease is not currently valid")
    try:
        VerifyKey(bytes.fromhex(expected_public_key)).verify(
            bytes.fromhex(lease.lease_hash), bytes.fromhex(lease.signature)
        )
    except (BadSignatureError, ValueError) as error:
        raise CensusExecutionError("lease signature mismatch") from error


class RetrievalRecord(FrozenModel):
    schema_version: Literal["inbar.iter001.census-retrieval-record.v1"] = (
        "inbar.iter001.census-retrieval-record.v1"
    )
    session_id: Identifier
    candidate_id: Identifier
    request_uri: str = Field(min_length=1)
    final_uri: str = Field(min_length=1)
    redirect_hops: tuple[str, ...]
    retrieved_at: datetime
    response_bytes: int = Field(ge=0)
    response_sha256: Sha256

    @model_validator(mode="after")
    def retrieval_time_is_aware(self) -> Self:
        if self.retrieved_at.tzinfo is None or self.retrieved_at.utcoffset() is None:
            raise ValueError("retrieval time must be timezone-aware")
        return self


class CensusExecutionBinding(FrozenModel):
    """Bound into every executed census report: which lease and frame produced it."""

    schema_version: Literal["inbar.iter001.census-execution-binding.v1"] = (
        "inbar.iter001.census-execution-binding.v1"
    )
    session_id: Identifier
    lease_hash: Sha256
    frame_registry_artifact_sha256: Sha256
    retrieval_count: int = Field(ge=0)
    retrieved_bytes: int = Field(ge=0)


# A transport receives a URI and returns (status, final_uri, redirect_hops, body). It exists
# so every control runs without live network access; the production transport is the only
# code path that opens a socket.
Transport = Callable[[str], tuple[int, str, tuple[str, ...], bytes]]


def https_certifi_transport(uri: str) -> tuple[int, str, tuple[str, ...], bytes]:
    """Production transport: HTTPS GET with certifi verification, bounded redirects."""
    hops: list[str] = []
    current = uri
    context = ssl.create_default_context(cafile=certifi.where())
    for _ in range(MAX_REDIRECT_HOPS + 1):
        if urllib.parse.urlsplit(current).scheme != "https":
            raise CensusExecutionError("retrieval transport is https-only")
        request = urllib.request.Request(current, method="GET")  # noqa: S310 - scheme enforced above
        try:
            with urllib.request.urlopen(  # noqa: S310 - scheme enforced above
                request, timeout=60, context=context
            ) as response:
                if response.status in (301, 302, 303, 307, 308):
                    location = response.headers.get("Location")
                    if not location:
                        raise CensusExecutionError("redirect without a location")
                    hops.append(current)
                    current = urllib.parse.urljoin(current, location)
                    continue
                body = response.read(_MAX_SINGLE_RESPONSE_BYTES + 1)
                return response.status, current, tuple(hops), body
        except urllib.error.URLError as error:
            raise CensusExecutionError(f"retrieval failed: {error.reason}") from error
    raise CensusExecutionError("redirect depth exceeded")


class CensusSession:
    """One leased retrieval session over the committed frame.

    Refusals happen before network contact: an invalid lease, a candidate with a recorded
    failing hard gate, a host outside the frame registry, or a request that would exceed the
    session byte ceiling all stop at this boundary.
    """

    def __init__(
        self,
        repo_root: Path,
        lease: CensusExecutionLease,
        *,
        transport: Transport | None = None,
        now: Callable[[], datetime] | None = None,
        expected_public_key: Ed25519PublicKey = OWNER_PUBLIC_KEY,
    ) -> None:
        self._root = repo_root.resolve(strict=True)
        registry_bytes = (self._root / FRAME_REGISTRY_PATH).read_bytes()
        verify_census_lease(
            lease,
            frame_registry_bytes=registry_bytes,
            expected_public_key=expected_public_key,
            at=(now or _utc_now)(),
        )
        self._lease = lease
        self._registry = FrameRegistry.model_validate_json(registry_bytes)
        self._allowed_hosts = self._registry.allowed_hosts()
        self._transport = transport or https_certifi_transport
        self._now = now or _utc_now
        self._retrieved_bytes = 0
        self._failed_candidates: set[str] = set()
        self._records: list[RetrievalRecord] = []
        store = self._root / LOCAL_STORE_ROOT / lease.session_id
        if store.exists():
            # One lease, one session: a pre-existing store means this session identifier
            # already ran, and a replay could launder a fresh ceiling onto old work.
            raise CensusExecutionError("session store already exists; a lease is single-use")
        (store / "blobs").mkdir(parents=True)
        self._store = store

    def record_failed_gate(self, candidate_id: str) -> None:
        self._failed_candidates.add(candidate_id)

    def retrieve(self, candidate_id: str, uri: str) -> RetrievalRecord:
        moment = self._now()
        if not self._lease.not_before <= moment < self._lease.expires_at:
            raise CensusExecutionError("lease is not currently valid")
        if candidate_id in self._failed_candidates:
            raise CensusExecutionError(
                "candidate has a recorded failing hard gate; the stop rule forbids retrieval"
            )
        split = urllib.parse.urlsplit(uri)
        if split.scheme != "https":
            raise CensusExecutionError("retrieval transport is https-only")
        if (split.hostname or "") not in self._allowed_hosts:
            raise CensusExecutionError("retrieval host is outside the committed frame registry")
        status, final_uri, hops, body = self._transport(uri)
        if status != 200:
            raise CensusExecutionError(f"retrieval returned status {status}")
        if len(hops) > MAX_REDIRECT_HOPS:
            raise CensusExecutionError("redirect depth exceeded")
        if self._retrieved_bytes + len(body) > self._lease.max_retrieved_bytes:
            raise CensusExecutionError("retrieval would exceed the session's frozen byte ceiling")
        self._retrieved_bytes += len(body)
        digest = hashlib.sha256(body).hexdigest()
        blob_path = self._store / "blobs" / digest
        if not blob_path.exists():
            blob_path.write_bytes(body)
        record = RetrievalRecord(
            session_id=self._lease.session_id,
            candidate_id=candidate_id,
            request_uri=uri,
            final_uri=final_uri,
            redirect_hops=hops,
            retrieved_at=moment,
            response_bytes=len(body),
            response_sha256=digest,
        )
        self._records.append(record)
        manifest = self._store / "manifest.jsonl"
        with manifest.open("a", encoding="utf-8") as handle:
            handle.write(record.model_dump_json() + "\n")
        return record

    def execution_binding(self) -> CensusExecutionBinding:
        return CensusExecutionBinding(
            session_id=self._lease.session_id,
            lease_hash=self._lease.lease_hash,
            frame_registry_artifact_sha256=self._lease.frame_registry_artifact_sha256,
            retrieval_count=len(self._records),
            retrieved_bytes=self._retrieved_bytes,
        )


def _utc_now() -> datetime:
    return datetime.now(UTC)


def write_census_lease(repo_root: Path, lease: CensusExecutionLease, path: str) -> Path:
    target = repo_root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(canonical_json_pretty(lease.model_dump(mode="json")))
    return target
