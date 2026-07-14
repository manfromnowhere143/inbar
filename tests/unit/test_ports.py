from __future__ import annotations

from fieldtrue.ports import (
    ArtifactStore,
    EvidenceSource,
    HypothesisEngine,
    MonitorCompiler,
    RecoveryVerifier,
    RemoteJobScheduler,
)
from fieldtrue.ports import (
    TestExecutor as ExecutorPort,
)
from fieldtrue.ports import (
    TestPlanner as PlannerPort,
)


def test_provider_neutral_port_surface_is_importable() -> None:
    protocols = (
        ArtifactStore,
        EvidenceSource,
        HypothesisEngine,
        MonitorCompiler,
        RecoveryVerifier,
        RemoteJobScheduler,
        ExecutorPort,
        PlannerPort,
    )
    assert {protocol.__name__ for protocol in protocols} == {
        "ArtifactStore",
        "EvidenceSource",
        "HypothesisEngine",
        "MonitorCompiler",
        "RecoveryVerifier",
        "RemoteJobScheduler",
        "TestExecutor",
        "TestPlanner",
    }
