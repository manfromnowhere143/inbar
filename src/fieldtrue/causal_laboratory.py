"""Causal-laboratory harness: paired branches, sealed injection, and adjudication.

Authorized by owner-approval receipt `iter001-causal-laboratory-owner-approval-004`
(`approve_causal_laboratory_implementation_only`) over Amendment 004 at proposal commit
`204ded16af24b84a51a85faed11140e1899ad1fd`.

These primitives authorize implementation only. A simulation campaign requires a per-session
compute lease signed by the owner governance key. A simulator branch never counts as a physical
incident: a causal-laboratory result establishes that the method works inside the simulator and
nothing about the physical world.

The plane exists because a simulator injects its own ground truth. The census cannot obtain
sealed mechanism truth without a human reading a record, which exposes that reader under
condition C6. Here the mechanism is injected, so the truth is known by construction and no
reader is exposed: the full method — a hypothesis proposer that commits before truth, a
discriminating-test selection, a recovery, and an outcome adjudicator — can be built and tested
end to end without a second unexposed reviewer.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final, Literal, Self

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey
from pydantic import Field, model_validator

from fieldtrue.canonical import sha256_value
from fieldtrue.census import (
    CEILING_CPU_SECONDS,
    CEILING_PEAK_MEMORY_BYTES,
    CEILING_WALL_SECONDS,
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

AMENDMENT_ID: Final = "iter001_004"
APPROVED_PROPOSAL_COMMIT: Final = "204ded16af24b84a51a85faed11140e1899ad1fd"
AMENDMENT_DOCUMENT_SHA256: Final = (
    "1f9f5a17d9611bbf3383ccb4ca8bae91053431ca57cf4d48c989ae6e5bae0cac"
)
MACHINE_PROPOSAL_SHA256: Final = "3f2b77934b81b6183b5b5e1bb9552406b7ee580746debab7713088014fc5c00f"
OWNER_APPROVAL_RECEIPT_HASH: Final = (
    "59a620b145bc8803e73bc34dcbd594dcfac7526a6ca313e3708ef2e3401db852"
)

UNKNOWN_MECHANISM_KEY: Final = "unknown"


class CausalLaboratoryError(ValueError):
    """A branch set, sealed mechanism, lease, or adjudication is invalid."""


# --- Mechanism ontology -------------------------------------------------------------


class MechanismClass(FrozenModel):
    """One known fault mechanism. Its key is derived from its canonical definition.

    Incident, site, filename, time, and truth tokens can never distinguish a class; only the
    physical definition can, exactly as the shortcut ontology requires.
    """

    schema_version: Literal["inbar.iter001.lab-mechanism-class.v1"] = (
        "inbar.iter001.lab-mechanism-class.v1"
    )
    name: Identifier
    causal_locus: str = Field(min_length=1)
    failure_mode: str = Field(min_length=1)
    definition: str = Field(min_length=1)

    @property
    def key(self) -> str:
        return sha256_value(
            {
                "schema_version": "inbar.iter001.lab-mechanism-class.v1",
                "causal_locus": self.causal_locus,
                "failure_mode": self.failure_mode,
                "definition": self.definition,
                "name": self.name,
            }
        )


class MechanismOntology(FrozenModel):
    schema_version: Literal["inbar.iter001.lab-mechanism-ontology.v1"] = (
        "inbar.iter001.lab-mechanism-ontology.v1"
    )
    classes: tuple[MechanismClass, ...] = Field(min_length=2)

    @model_validator(mode="after")
    def keys_are_unique_and_not_reserved(self) -> Self:
        keys = [c.key for c in self.classes]
        if len(set(keys)) != len(keys):
            raise ValueError("mechanism classes must have unique keys")
        if UNKNOWN_MECHANISM_KEY in {c.name for c in self.classes}:
            raise ValueError("a mechanism class may not use the reserved unknown name")
        return self

    @property
    def known_keys(self) -> frozenset[str]:
        return frozenset(c.key for c in self.classes)

    @property
    def ontology_hash(self) -> str:
        return sha256_value(
            {
                "schema_version": self.schema_version,
                "classes": [c.model_dump(mode="json") for c in self.classes],
            }
        )


# --- Sealed injected mechanism (the truth record) -----------------------------------


class SealedMechanism(FrozenModel):
    """The injected mechanism, content-addressed and sealed.

    The public artifact is the salted commitment only. The injected key and salt are the
    truth plaintext and remain custodian-only until adjudication. The commitment binds the
    ontology hash, so a mechanism cannot be reinterpreted under a different ontology.
    """

    schema_version: Literal["inbar.iter001.lab-sealed-mechanism.v1"] = (
        "inbar.iter001.lab-sealed-mechanism.v1"
    )
    ontology_hash: Sha256
    commitment: Sha256

    @staticmethod
    def commit(*, ontology_hash: str, injected_key: str, salt_hex: str) -> SealedMechanism:
        if len(salt_hex) != 64 or any(c not in "0123456789abcdef" for c in salt_hex):
            raise CausalLaboratoryError("mechanism salt must be 64 lowercase hex characters")
        commitment = sha256_value(
            {
                "schema_version": "inbar.iter001.lab-sealed-mechanism-commitment.v1",
                "injected_key": injected_key,
                "ontology_hash": ontology_hash,
                "salt_hex": salt_hex,
            }
        )
        return SealedMechanism(ontology_hash=ontology_hash, commitment=commitment)

    def opens_to(self, *, injected_key: str, salt_hex: str) -> bool:
        candidate = SealedMechanism.commit(
            ontology_hash=self.ontology_hash, injected_key=injected_key, salt_hex=salt_hex
        )
        return candidate.commitment == self.commitment


# --- Snapshot and paired branches ---------------------------------------------------


class Snapshot(FrozenModel):
    """A frozen initial simulator state. Every branch descends from exactly one."""

    schema_version: Literal["inbar.iter001.lab-snapshot.v1"] = "inbar.iter001.lab-snapshot.v1"
    simulator_id: Identifier
    config_sha256: Sha256
    initial_state_sha256: Sha256
    seed: int = Field(ge=0)

    @property
    def snapshot_hash(self) -> str:
        return sha256_value(
            {
                "schema_version": self.schema_version,
                "config_sha256": self.config_sha256,
                "initial_state_sha256": self.initial_state_sha256,
                "seed": self.seed,
                "simulator_id": self.simulator_id,
            }
        )


class BranchKind(StrEnum):
    NO_OP = "no_op"
    TARGETED_TEST = "targeted_test"
    WRONG_BUT_SAFE = "wrong_but_safe"
    RECOVERY = "recovery"
    BLOCKED_UNSAFE = "blocked_unsafe"


REQUIRED_BRANCHES: Final[frozenset[BranchKind]] = frozenset(BranchKind)


class Branch(FrozenModel):
    schema_version: Literal["inbar.iter001.lab-branch.v1"] = "inbar.iter001.lab-branch.v1"
    kind: BranchKind
    snapshot_hash: Sha256
    action_sha256: Sha256
    executed: bool
    settled_state_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def blocked_unsafe_is_never_executed(self) -> Self:
        if self.kind is BranchKind.BLOCKED_UNSAFE:
            if self.executed or self.settled_state_sha256 is not None:
                raise ValueError("a blocked_unsafe branch must be refused, never executed")
        elif not self.executed or self.settled_state_sha256 is None:
            raise ValueError("an executed branch must record a settled state")
        return self


class BranchSet(FrozenModel):
    schema_version: Literal["inbar.iter001.lab-branch-set.v1"] = "inbar.iter001.lab-branch-set.v1"
    snapshot: Snapshot
    branches: tuple[Branch, ...]

    @model_validator(mode="after")
    def exactly_the_five_branches_from_one_snapshot(self) -> Self:
        kinds = [b.kind for b in self.branches]
        if len(set(kinds)) != len(kinds):
            raise ValueError("each branch kind may appear at most once")
        if set(kinds) != set(REQUIRED_BRANCHES):
            raise ValueError("a branch set must contain exactly the five branch kinds")
        expected = self.snapshot.snapshot_hash
        for branch in self.branches:
            if branch.snapshot_hash != expected:
                raise ValueError("every branch must descend from the frozen snapshot")
        return self


# --- Hypothesis commitment (proposer, blind to injected truth) ----------------------


class LabHypothesisSet(FrozenModel):
    """The proposer's committed hypotheses, formed blind to the injected mechanism.

    At least two known mechanism keys and exactly one reserved unknown, mirroring the physical
    open-world ambiguity gate. The diagnosis names the single key the method selected.
    """

    schema_version: Literal["inbar.iter001.lab-hypothesis-set.v1"] = (
        "inbar.iter001.lab-hypothesis-set.v1"
    )
    ontology_hash: Sha256
    known_keys: tuple[Sha256, ...] = Field(min_length=2)
    includes_unknown: Literal[True] = True
    committed_at: datetime

    @model_validator(mode="after")
    def known_keys_are_unique_and_time_is_aware(self) -> Self:
        if len(set(self.known_keys)) != len(self.known_keys):
            raise ValueError("hypothesis known keys must be unique")
        if self.committed_at.tzinfo is None or self.committed_at.utcoffset() is None:
            raise ValueError("hypothesis commitment time must be timezone-aware")
        return self

    @property
    def candidate_keys(self) -> frozenset[str]:
        return frozenset(self.known_keys) | {UNKNOWN_MECHANISM_KEY}

    @property
    def hypothesis_hash(self) -> str:
        return sha256_value(
            {
                "schema_version": self.schema_version,
                "committed_at": self.committed_at.isoformat(),
                "includes_unknown": True,
                "known_keys": list(self.known_keys),
                "ontology_hash": self.ontology_hash,
            }
        )


# --- Compute lease (owner ceremony, parallel to the census execution lease) ---------


class CausalLabComputeLease(FrozenModel):
    schema_version: Literal["inbar.iter001.lab-compute-lease.v1"] = (
        "inbar.iter001.lab-compute-lease.v1"
    )
    lease_id: Identifier
    session_id: Identifier
    amendment_document_artifact_sha256: Sha256
    machine_proposal_artifact_sha256: Sha256
    owner_approval_receipt_hash: Sha256
    ontology_hash: Sha256
    max_cpu_seconds: float = Field(gt=0)
    max_wall_seconds: float = Field(gt=0)
    max_peak_memory_bytes: int = Field(gt=0)
    max_gpu_seconds: Literal[0] = 0
    not_before: datetime
    expires_at: datetime
    nonce: Sha256
    owner_ed25519_public_key: Ed25519PublicKey
    proposal_git_commit: GitObjectId
    lease_hash: Sha256
    signature: HexSignature

    @model_validator(mode="after")
    def window_and_hash_are_well_formed(self) -> Self:
        for value in (self.not_before, self.expires_at):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("lease timestamps must be timezone-aware")
        if self.expires_at <= self.not_before:
            raise ValueError("lease expiry must follow its start")
        if sha256_value(_lab_lease_body(self)) != self.lease_hash:
            raise ValueError("lease hash mismatch")
        return self


def _lab_lease_body(lease: CausalLabComputeLease | dict[str, Any]) -> dict[str, Any]:
    body = (
        lease.model_dump(mode="json") if isinstance(lease, CausalLabComputeLease) else dict(lease)
    )
    body.pop("lease_hash", None)
    body.pop("signature", None)
    return body


def issue_lab_compute_lease(
    signing_key: SigningKey,
    *,
    lease_id: Identifier,
    session_id: Identifier,
    ontology_hash: Sha256,
    not_before: datetime,
    expires_at: datetime,
    nonce: Sha256,
) -> CausalLabComputeLease:
    """Owner ceremony. The ceiling values are not parameters, so no lease can widen a run.

    GPU seconds are typed to zero: the causal laboratory is local and offline.
    """
    body: dict[str, Any] = {
        "schema_version": "inbar.iter001.lab-compute-lease.v1",
        "lease_id": lease_id,
        "session_id": session_id,
        "amendment_document_artifact_sha256": AMENDMENT_DOCUMENT_SHA256,
        "machine_proposal_artifact_sha256": MACHINE_PROPOSAL_SHA256,
        "owner_approval_receipt_hash": OWNER_APPROVAL_RECEIPT_HASH,
        "ontology_hash": ontology_hash,
        "max_cpu_seconds": CEILING_CPU_SECONDS,
        "max_wall_seconds": CEILING_WALL_SECONDS,
        "max_peak_memory_bytes": CEILING_PEAK_MEMORY_BYTES,
        "max_gpu_seconds": 0,
        "not_before": not_before,
        "expires_at": expires_at,
        "nonce": nonce,
        "owner_ed25519_public_key": signing_key.verify_key.encode().hex(),
        "proposal_git_commit": APPROVED_PROPOSAL_COMMIT,
    }
    normalized = json.loads(
        CausalLabComputeLease.model_construct(**body).model_dump_json(
            exclude={"lease_hash", "signature"}
        )
    )
    lease_hash = sha256_value(normalized)
    signature = signing_key.sign(bytes.fromhex(lease_hash)).signature.hex()
    return CausalLabComputeLease.model_validate(
        {**normalized, "lease_hash": lease_hash, "signature": signature}
    )


def verify_lab_compute_lease(
    lease: CausalLabComputeLease,
    *,
    ontology_hash: str,
    expected_public_key: Ed25519PublicKey = OWNER_PUBLIC_KEY,
    at: datetime | None = None,
) -> None:
    """Fail closed on any scope, ontology, ceiling, window, or signature mismatch.

    `expected_public_key` pins the signer and defaults to the frozen owner key, so a real
    campaign only accepts an owner-signed lease; a test injects a deterministic key.
    """
    checked_at = at or datetime.now(UTC)
    if checked_at.tzinfo is None or checked_at.utcoffset() is None:
        raise CausalLaboratoryError("lease verification time must be timezone-aware")
    expected = {
        "amendment_document_artifact_sha256": AMENDMENT_DOCUMENT_SHA256,
        "machine_proposal_artifact_sha256": MACHINE_PROPOSAL_SHA256,
        "owner_approval_receipt_hash": OWNER_APPROVAL_RECEIPT_HASH,
        "owner_ed25519_public_key": expected_public_key,
        "proposal_git_commit": APPROVED_PROPOSAL_COMMIT,
        "max_cpu_seconds": CEILING_CPU_SECONDS,
        "max_wall_seconds": CEILING_WALL_SECONDS,
        "max_peak_memory_bytes": CEILING_PEAK_MEMORY_BYTES,
        "max_gpu_seconds": 0,
    }
    observed = lease.model_dump(mode="json")
    if any(observed[field] != value for field, value in expected.items()):
        raise CausalLaboratoryError("lease differs from the approved causal-laboratory scope")
    if lease.ontology_hash != ontology_hash:
        raise CausalLaboratoryError("lease does not bind the committed mechanism ontology")
    if not lease.not_before <= checked_at < lease.expires_at:
        raise CausalLaboratoryError("lease is not currently valid")
    try:
        VerifyKey(bytes.fromhex(expected_public_key)).verify(
            bytes.fromhex(lease.lease_hash), bytes.fromhex(lease.signature)
        )
    except (BadSignatureError, ValueError) as error:
        raise CausalLaboratoryError("lease signature mismatch") from error


# --- Episode report and adjudication ------------------------------------------------


class EpisodeReport(FrozenModel):
    """One causal-laboratory episode. Binds the sealed truth, the blind hypotheses, the
    branch set, and the method's diagnosis, before any truth reveal."""

    schema_version: Literal["inbar.iter001.lab-episode-report.v1"] = (
        "inbar.iter001.lab-episode-report.v1"
    )
    episode_id: Identifier
    amendment_document_artifact_sha256: Sha256
    machine_proposal_artifact_sha256: Sha256
    owner_approval_receipt_hash: Sha256
    ontology_hash: Sha256
    sealed_mechanism: SealedMechanism
    branch_set: BranchSet
    hypothesis_set: LabHypothesisSet
    diagnosis_key: str = Field(min_length=1)
    produced_at: datetime

    @model_validator(mode="after")
    def binds_the_approved_artifacts_and_is_internally_consistent(self) -> Self:
        if self.amendment_document_artifact_sha256 != AMENDMENT_DOCUMENT_SHA256:
            raise ValueError("episode does not bind the approved amendment document")
        if self.machine_proposal_artifact_sha256 != MACHINE_PROPOSAL_SHA256:
            raise ValueError("episode does not bind the approved machine proposal")
        if self.owner_approval_receipt_hash != OWNER_APPROVAL_RECEIPT_HASH:
            raise ValueError("episode does not bind the owner-approval receipt")
        if self.sealed_mechanism.ontology_hash != self.ontology_hash:
            raise ValueError("sealed mechanism ontology differs from the episode ontology")
        if self.hypothesis_set.ontology_hash != self.ontology_hash:
            raise ValueError("hypothesis set ontology differs from the episode ontology")
        if self.produced_at.tzinfo is None or self.produced_at.utcoffset() is None:
            raise ValueError("episode time must be timezone-aware")
        # The method may only diagnose a key it committed to as a candidate. A diagnosis
        # outside the blind hypothesis set is a leak, not a diagnosis.
        if self.diagnosis_key not in self.hypothesis_set.candidate_keys:
            raise ValueError("diagnosis names a key outside the committed hypothesis set")
        # The hypotheses must be committed no later than the episode is produced.
        if self.hypothesis_set.committed_at > self.produced_at:
            raise ValueError("hypotheses were committed after the episode was produced")
        return self


class AdjudicationResult(FrozenModel):
    schema_version: Literal["inbar.iter001.lab-adjudication.v1"] = (
        "inbar.iter001.lab-adjudication.v1"
    )
    episode_id: Identifier
    injected_key: str
    diagnosis_key: str
    commitment_opened: Literal[True]
    diagnosis_correct: bool
    injected_was_unknown: bool
    adjudicated_at: datetime


def adjudicate_episode(
    episode: EpisodeReport,
    *,
    injected_key: str,
    salt_hex: str,
    known_ontology_keys: frozenset[str],
    at: datetime | None = None,
) -> AdjudicationResult:
    """Reveal the sealed truth and adjudicate the method's diagnosis against it.

    Because the truth was injected rather than read from a record, this adjudication establishes
    it without exposing any reader, so condition C6 does not apply. The reveal must open the
    sealed commitment exactly; an injected key that is neither a known ontology key nor the
    reserved unknown is invalid.
    """
    adjudicated_at = at or datetime.now(UTC)
    if adjudicated_at.tzinfo is None or adjudicated_at.utcoffset() is None:
        raise CausalLaboratoryError("adjudication time must be timezone-aware")
    if injected_key != UNKNOWN_MECHANISM_KEY and injected_key not in known_ontology_keys:
        raise CausalLaboratoryError("injected key is neither a known ontology key nor unknown")
    if not episode.sealed_mechanism.opens_to(injected_key=injected_key, salt_hex=salt_hex):
        raise CausalLaboratoryError("reveal does not open the sealed mechanism commitment")
    return AdjudicationResult(
        episode_id=episode.episode_id,
        injected_key=injected_key,
        diagnosis_key=episode.diagnosis_key,
        commitment_opened=True,
        diagnosis_correct=(episode.diagnosis_key == injected_key),
        injected_was_unknown=(injected_key == UNKNOWN_MECHANISM_KEY),
        adjudicated_at=adjudicated_at,
    )


# --- Deterministic reference simulator (the first provider-neutral adapter) ----------
#
# A campaign runs against a simulator port. Basilisk is the intended production adapter; this
# reference adapter is deterministic integer fixed-point arithmetic so a branch's content hash
# is identical on every platform in the test matrix, which floating point would not guarantee.
# It is rich enough to make fault modes discriminable under the right probe and to leave a fault
# invisible under a no-op, which is what a paired-branch episode needs.


class ReferenceFaultConfig(FrozenModel):
    """A scalar linear recurrence x' = (gain * x)//100 + (drive * u)//100 + bias, per step."""

    schema_version: Literal["inbar.iter001.lab-reference-config.v1"] = (
        "inbar.iter001.lab-reference-config.v1"
    )
    gain: int
    drive: int
    bias: int
    steps: int = Field(ge=1, le=4096)

    @property
    def config_sha256(self) -> str:
        return sha256_value(
            {
                "schema_version": self.schema_version,
                "bias": self.bias,
                "drive": self.drive,
                "gain": self.gain,
                "steps": self.steps,
            }
        )


# The reference ontology. `unknown` is never a class; it is the reserved key an episode may
# inject and a proposer must always carry.
REFERENCE_ONTOLOGY: Final = MechanismOntology(
    classes=(
        MechanismClass(
            name="actuator_loss",
            causal_locus="actuator",
            failure_mode="drive_attenuated",
            definition="The commanded drive reaches the plant at a fraction of its magnitude.",
        ),
        MechanismClass(
            name="sensor_bias",
            causal_locus="sensor",
            failure_mode="additive_offset",
            definition="A constant additive offset corrupts the measured output.",
        ),
        MechanismClass(
            name="gain_drift",
            causal_locus="plant",
            failure_mode="open_loop_gain_increase",
            definition="The open-loop gain drifts above its nominal value.",
        ),
    )
)


def _reference_mechanism_transform(
    injected_key: str, config: ReferenceFaultConfig
) -> tuple[int, int, int]:
    """Return the faulted (gain, drive, bias) for a reference mechanism key or the nominal set."""
    by_name = {c.key: c.name for c in REFERENCE_ONTOLOGY.classes}
    name = by_name.get(injected_key, UNKNOWN_MECHANISM_KEY)
    gain, drive, bias = config.gain, config.drive, config.bias
    if name == "actuator_loss":
        return gain, drive // 10, bias
    if name == "sensor_bias":
        return gain, drive, bias + 1000
    if name == "gain_drift":
        return gain + 40, drive, bias
    # unknown or unrecognized: nominal dynamics, an unmodeled departure the catalog cannot name.
    return gain, drive, bias


def reference_snapshot(*, config: ReferenceFaultConfig, initial_state: int, seed: int) -> Snapshot:
    return Snapshot(
        simulator_id="inbar-reference-simulator-v1",
        config_sha256=config.config_sha256,
        initial_state_sha256=sha256_value(
            {"schema_version": "inbar.iter001.lab-reference-state.v1", "x": initial_state}
        ),
        seed=seed,
    )


def _run_reference(
    *,
    config: ReferenceFaultConfig,
    initial_state: int,
    seed: int,
    injected_key: str,
    action: tuple[int, ...],
) -> tuple[int, tuple[int, ...]]:
    """Deterministic run. Returns the settled state and the observed telemetry tuple."""
    gain, drive, bias = _reference_mechanism_transform(injected_key, config)
    x = initial_state
    telemetry: list[int] = []
    for step in range(config.steps):
        u = action[step] if step < len(action) else 0
        # Deterministic bounded disturbance from the seed and step, integer only.
        disturbance = (
            int.from_bytes(hashlib.sha256(f"{seed}:{step}".encode()).digest()[:2], "big") % 7 - 3
        )
        x = (gain * x) // 100 + (drive * u) // 100 + bias
        telemetry.append(x + disturbance)
    return x, tuple(telemetry)


def reference_action_hash(action: tuple[int, ...]) -> str:
    return sha256_value(
        {"schema_version": "inbar.iter001.lab-reference-action.v1", "u": list(action)}
    )


def reference_branch(
    *,
    kind: BranchKind,
    snapshot: Snapshot,
    config: ReferenceFaultConfig,
    initial_state: int,
    injected_key: str,
    action: tuple[int, ...],
) -> tuple[Branch, tuple[int, ...]]:
    """Build one branch and its telemetry. blocked_unsafe is refused, never run."""
    action_hash = reference_action_hash(action)
    if kind is BranchKind.BLOCKED_UNSAFE:
        return (
            Branch(
                kind=kind,
                snapshot_hash=snapshot.snapshot_hash,
                action_sha256=action_hash,
                executed=False,
                settled_state_sha256=None,
            ),
            (),
        )
    settled, telemetry = _run_reference(
        config=config,
        initial_state=initial_state,
        seed=snapshot.seed,
        injected_key=injected_key,
        action=action,
    )
    return (
        Branch(
            kind=kind,
            snapshot_hash=snapshot.snapshot_hash,
            action_sha256=action_hash,
            executed=True,
            settled_state_sha256=sha256_value(
                {"schema_version": "inbar.iter001.lab-reference-state.v1", "x": settled}
            ),
        ),
        telemetry,
    )
