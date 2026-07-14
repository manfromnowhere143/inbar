"""Provider-neutral interfaces for mission execution."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from fieldtrue.domain import (
    ArtifactRef,
    AssuranceCertificate,
    CausalHypothesis,
    DiscriminatingTest,
    EvidenceBundle,
    HypothesisSet,
    JobSpec,
    RecoveryPlan,
    SafetyEnvelope,
    SelectedTest,
    TestObservation,
    VerificationResult,
)


class EvidenceSource(Protocol):
    def load_case(self, incident_id: str) -> EvidenceBundle: ...


class HypothesisEngine(Protocol):
    @property
    def engine_id(self) -> str: ...

    def infer(self, evidence: EvidenceBundle) -> HypothesisSet: ...


class TestPlanner(Protocol):
    @property
    def planner_id(self) -> str: ...

    def select(
        self,
        hypotheses: HypothesisSet,
        candidates: tuple[DiscriminatingTest, ...],
        envelope: SafetyEnvelope,
    ) -> SelectedTest: ...


class TestExecutor(Protocol):
    @property
    def executor_id(self) -> str: ...

    def preview(
        self,
        selected: SelectedTest,
        candidate: DiscriminatingTest,
        envelope: SafetyEnvelope,
    ) -> dict[str, Any]: ...

    def execute(
        self,
        selected: SelectedTest,
        candidate: DiscriminatingTest,
        envelope: SafetyEnvelope,
    ) -> TestObservation: ...


class RecoveryVerifier(Protocol):
    @property
    def verifier_id(self) -> str: ...

    def verify(self, plan: RecoveryPlan) -> VerificationResult: ...


class ArtifactStore(Protocol):
    def put(self, source: Path, *, artifact_id: str, media_type: str) -> ArtifactRef: ...

    def get(self, artifact: ArtifactRef, destination: Path) -> Path: ...


class RemoteJobScheduler(Protocol):
    def plan(self, spec: JobSpec) -> dict[str, Any]: ...

    def preflight(self, spec: JobSpec) -> dict[str, Any]: ...

    def submit(self, spec: JobSpec) -> str: ...

    def poll(self, handle: str) -> dict[str, Any]: ...

    def collect(self, handle: str) -> tuple[ArtifactRef, ...]: ...


class MonitorCompiler(Protocol):
    def compile(
        self,
        hypotheses: tuple[CausalHypothesis, ...],
        verification: VerificationResult,
    ) -> AssuranceCertificate: ...
