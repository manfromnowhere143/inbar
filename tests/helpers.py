from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

from fieldtrue.adapters.adapt import (
    AdaptDatasetLock,
    AdaptResourceLock,
    ResourceReceipt,
)
from fieldtrue.domain import (
    ArtifactRef,
    CausalHypothesis,
    DiscriminatingTest,
    ExecutionAuthority,
    HypothesisSet,
    SafetyEnvelope,
    TestOutcomeModel,
)
from fieldtrue.runtime import RuntimeIdentity

HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
APPROVAL_HASH = "d" * 64


def artifact(identifier: str = "artifact-1") -> ArtifactRef:
    return ArtifactRef(
        artifact_id=identifier,
        uri=f"artifacts/{identifier}.json",
        sha256=HASH_A,
        bytes=12,
        media_type="application/json",
        source_authority="test-fixture",
        clock_domain="fixture-clock",
        license_ref="internal-fixture",
    )


def hypotheses() -> HypothesisSet:
    return HypothesisSet(
        incident_id="incident-1",
        proposer_id="fixture-hypothesis-engine",
        hypotheses=(
            CausalHypothesis(
                hypothesis_id="power-open",
                description="Power relay failed open",
                prior=0.45,
            ),
            CausalHypothesis(
                hypothesis_id="sensor-bias",
                description="Voltage sensor is biased",
                prior=0.45,
            ),
            CausalHypothesis(
                hypothesis_id="unknown",
                description="Mechanism is outside the known catalog",
                prior=0.10,
                unknown=True,
            ),
        ),
    )


def informative_test(
    *,
    test_id: str = "toggle-backup-feed",
    risk: float = 0.1,
    authority: ExecutionAuthority = ExecutionAuthority.REPLAY,
    approved: bool = True,
    approval_hash: str | None = None,
) -> DiscriminatingTest:
    return DiscriminatingTest(
        test_id=test_id,
        description="Briefly toggle the isolated backup feed",
        authority=authority,
        approved=approved,
        cost_units=1.0,
        duration_seconds=1.0,
        risk=risk,
        preconditions=("load-isolated",),
        approval_receipt_hash=approval_hash,
        outcome_model=(
            TestOutcomeModel(
                outcome_id="voltage-recovers",
                probability_by_hypothesis={
                    "power-open": 0.9,
                    "sensor-bias": 0.1,
                    "unknown": 0.5,
                },
            ),
            TestOutcomeModel(
                outcome_id="voltage-unchanged",
                probability_by_hypothesis={
                    "power-open": 0.1,
                    "sensor-bias": 0.9,
                    "unknown": 0.5,
                },
            ),
        ),
    )


def sham_test(*, test_id: str = "sham-toggle") -> DiscriminatingTest:
    return DiscriminatingTest(
        test_id=test_id,
        description="Budget-matched semantics-free control",
        authority=ExecutionAuthority.REPLAY,
        approved=True,
        cost_units=1.0,
        duration_seconds=1.0,
        risk=0.1,
        preconditions=("load-isolated",),
        outcome_model=(
            TestOutcomeModel(
                outcome_id="signal-high",
                probability_by_hypothesis={
                    "power-open": 0.5,
                    "sensor-bias": 0.5,
                    "unknown": 0.5,
                },
            ),
            TestOutcomeModel(
                outcome_id="signal-low",
                probability_by_hypothesis={
                    "power-open": 0.5,
                    "sensor-bias": 0.5,
                    "unknown": 0.5,
                },
            ),
        ),
    )


def envelope(*test_ids: str, max_risk: float = 0.2) -> SafetyEnvelope:
    return SafetyEnvelope(
        envelope_id="replay-envelope",
        authority=ExecutionAuthority.REPLAY,
        allowed_test_ids=test_ids or ("toggle-backup-feed",),
        max_risk=max_risk,
        satisfied_preconditions=("load-isolated",),
    )


def runtime_identity(*, dirty: bool = False) -> RuntimeIdentity:
    return RuntimeIdentity(
        git_commit="1" * 40,
        git_tree="2" * 40,
        repository_dirty=dirty,
        dirty_state_hash=HASH_A,
        lockfile_hash=HASH_B,
        python_version="3.12.2",
        platform="test-platform",
        command=("fieldtrue", "test"),
        provenance_state="observed-v1",
        python_interpreter_provenance_sha256="3" * 64,
        startup_provenance_sha256="4" * 64,
        environment_provenance_sha256="5" * 64,
        fieldtrue_source_sha256="6" * 64,
        loaded_module_closure_sha256="7" * 64,
        dependency_closure_sha256="8" * 64,
    )


def legacy_runtime_identity(*, dirty: bool = False) -> RuntimeIdentity:
    payload = runtime_identity(dirty=dirty).model_dump(mode="json")
    for field in (
        "provenance_state",
        "python_interpreter_provenance_sha256",
        "startup_provenance_sha256",
        "environment_provenance_sha256",
        "fieldtrue_source_sha256",
        "loaded_module_closure_sha256",
        "dependency_closure_sha256",
    ):
        payload.pop(field)
    return RuntimeIdentity.model_validate(payload)


def adapt_text(experiment_id: str = "001", *, unknown_row: bool = False) -> str:
    rows = [
        "\t".join(
            (
                "ExperimentControl",
                experiment_id,
                "OperationCode = D1",
                "OperationMode = 37",
                "TestArticleName = fixture",
                "FaultType = abrupt",
                "FaultMode = failed open",
                "FaultLocation = R1",
                "FaultInjection = software",
            )
        ),
        "SensorData\tTime\tV1\tS1",
        "AntagonistData\t2007-01-01 00:00:00 GMT-07:00\t24.0\t1",
        "UserCommand\t2007-01-01 00:00:01 GMT-07:00\tR1_CL\t1",
        "AntagonistCommand\t2007-01-01 00:00:01 GMT-07:00\tR1_CL\t0",
        (
            "FaultInject\t2007-01-01 00:00:02 GMT-07:00\tR1\tRelay\tStuck\tTRUE\t"
            "Sticks open\tAbrupt\tStuck At=0"
        ),
        "AntagonistData\t2007-01-01 00:00:02 GMT-07:00\t0.0\t0",
    ]
    if unknown_row:
        rows.append("MysteryRow\tvalue")
    return "\n".join(rows) + "\n"


def create_adapt_source(
    root: Path,
    *,
    count: int = 1,
    unknown_row: bool = False,
    unsafe_member: bool = False,
) -> tuple[AdaptDatasetLock, tuple[ResourceReceipt, ...]]:
    root.mkdir(parents=True, exist_ok=True)
    archive = root / "dataset_text.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as handle:
        if unsafe_member:
            handle.writestr("../escape.txt", "escape")
        else:
            for index in range(1, count + 1):
                experiment_id = f"{index:03d}"
                handle.writestr(
                    f"dataset_text/Exp_{experiment_id}_comp3_pb.txt",
                    adapt_text(experiment_id, unknown_row=unknown_row),
                )
    data = archive.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    resource = AdaptResourceLock(
        id="dataset-text",
        url="https://example.invalid/dataset_text.zip",
        filename="dataset_text.zip",
        sha256=digest,
        bytes=len(data),
        media_type="application/zip",
    )
    lock = AdaptDatasetLock(
        schema_version="fieldtrue.dataset-lock.v1",
        dataset_id="adapt-fixture",
        source_authority="fixture-authority",
        landing_page="https://example.invalid",
        license_status="internal-fixture",
        redistribution="fixture-only",
        resources=(resource,),
        expected_experiment_files=count,
        allowed_model_visible_rows=("AntagonistData", "UserCommand"),
        truth_only_rows=("ExperimentControl", "FaultInject", "AntagonistCommand"),
        limitations=(),
    )
    receipts = (
        ResourceReceipt(
            resource_id=resource.id,
            filename=resource.filename,
            sha256=digest,
            bytes=len(data),
            verified=True,
        ),
    )
    return lock, receipts
