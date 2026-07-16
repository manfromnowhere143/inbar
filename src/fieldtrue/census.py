"""Prospective source-screening census contracts for Iteration 001.

Authorized by owner-approval receipt `iter001-source-census-owner-approval-002`
(`approve_source_census_implementation_only`) over Amendment 002 at proposal commit
`13b2085173d1d3011626ef96cd9b4e447afb6b6e`.

These primitives authorize implementation only. They do not authorize retrieval, census
execution, acquisition, resource spend, physical action, a scientific verdict, a canonical
seal, or publication. A census pass is a nomination, never an admission: the complete
incident contract in the frozen parent hypothesis remains the sole admission gate, and no
census artifact contributes a scientific unit or counts toward the thirty-incident floor.
"""

from __future__ import annotations

import hashlib
import json
import re
import resource
import stat
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Final, Literal, Self

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from pydantic import Field, model_validator

from fieldtrue.canonical import canonical_json_pretty, sha256_value
from fieldtrue.domain import (
    Ed25519PublicKey,
    FrozenModel,
    GitObjectId,
    HexSignature,
    Identifier,
    Sha256,
)
from fieldtrue.git_trust import (
    GitTrustError,
    git_environment,
    trusted_git_executable,
    verify_repository_trust,
)
from fieldtrue.shortcut_contracts import (
    OWNER_ACTOR_ID,
    OWNER_ANCHOR_COMMIT,
    OWNER_ANCHOR_PATH,
    OWNER_ANCHOR_SHA256,
    OWNER_PUBLIC_KEY,
    OWNER_SIGNING_KEY_ID,
    OWNER_TRUST_BASIS,
    OwnerAmendmentApprovalReceipt,
)
from fieldtrue.shortcut_contracts import (
    OWNER_APPROVAL_PATH as AMENDMENT_001_RECEIPT_PATH,
)

AMENDMENT_ID: Final = "iter001_002"
ITERATION_ID: Final = "iter001_physical_causal_evidence_acquisition"
APPROVED_PROPOSAL_COMMIT: Final = "13b2085173d1d3011626ef96cd9b4e447afb6b6e"
AMENDMENT_DOCUMENT_PATH: Final = (
    "experiments/iter001_physical_causal_evidence_acquisition/AMENDMENT_002.md"
)
AMENDMENT_DOCUMENT_SHA256: Final = (
    "a0a152006542e475188342f0ba8524037472d50001406449edbb67a4364a3e82"
)
MACHINE_PROPOSAL_PATH: Final = "protocol/amendments/iter001_002.json"
MACHINE_PROPOSAL_SHA256: Final = "bb3f73b720c079d0bc58f22bc067a16fe08e8371bb94139f1f261583ae1c49d7"
OWNER_APPROVAL_PATH: Final = "protocol/approvals/iter001_002_owner_approval.json"
OWNER_APPROVAL_RECEIPT_HASH: Final = (
    "6be770e5b619c8a8a56c4718e3ceb10d52a23c93f92090fcd9a050eee9bf808d"
)
PREVIOUS_APPROVAL_RECEIPT_HASH: Final = (
    "482575c10bb58da6b867ee60587cefa290512fa6f09529a324cea3002fd616c3"
)
CENSUS_DECISION: Final = "approve_source_census_implementation_only"


# Frozen by Amendment 002 `resource_ceiling`. These are the amendment's values expressed in
# base units; they are not independently chosen here and cannot be widened without a new
# prospective amendment.
CEILING_CPU_SECONDS: Final = 4 * 3600.0
CEILING_WALL_SECONDS: Final = 2 * 3600.0
CEILING_PEAK_MEMORY_BYTES: Final = 16 * 1024**3
CEILING_RETRIEVED_BYTES: Final = 1 * 1024**3
CEILING_PEAK_STAGED_BYTES: Final = 2 * 1024**3


class CensusError(ValueError):
    """A census frame, locator, gate result, or verdict is invalid."""


class MutabilityClass(StrEnum):
    CONTENT_FROZEN = "content_frozen"
    MUTABLE_PAGE = "mutable_page"


class LocatorKind(StrEnum):
    PDF_PAGE = "pdf_page"
    SECTION_PATH = "section_path"
    LINE_RANGE = "line_range"
    RECORD_FIELD = "record_field"
    TABLE_CELL = "table_cell"


class FrozenIdentifierKind(StrEnum):
    DOI = "doi"
    VERSIONED_RECORD = "versioned_record"
    TAGGED_RELEASE = "tagged_release"
    AUTHORITY_ASSIGNED_DOCKET_OR_REPORT_NUMBER = "authority_assigned_docket_or_report_number"
    INDEPENDENT_ARCHIVAL_SNAPSHOT = "independent_archival_snapshot_publishing_its_own_content_hash"


class ObjectClass(StrEnum):
    DATASET_RELEASE = "dataset_release"
    INVESTIGATION_RECORD = "investigation_record"


class Stratum(StrEnum):
    PRIOR_EXPOSED = "prior_exposed"
    PROSPECTIVE = "prospective"


class CensusGate(StrEnum):
    RIGHTS_AND_TERMS = "rights_and_terms"
    IMMUTABLE_VERSION_OR_AUTHORITY_IDENTIFIER = "immutable_version_or_authority_identifier"
    PHYSICAL_IDENTITY_AND_SYSTEM_FAMILY = "physical_identity_and_system_family"
    OBJECT_CLASS_APPROPRIATE_EVIDENCE_PRESENCE = "object_class_appropriate_evidence_presence"
    MECHANISM_AUTHORITY = "mechanism_authority"
    PRE_OUTCOME_AMBIGUITY_AND_CHRONOLOGY = "pre_outcome_ambiguity_and_chronology"
    DIAGNOSTIC_ACTION_EXECUTION = "diagnostic_action_execution"
    RECOVERY_EXECUTION = "recovery_execution"
    INDEPENDENT_SETTLED_OUTCOME = "independent_settled_outcome"
    CLOCK_CONTRACT = "clock_contract"
    ROLE_INDEPENDENCE = "role_independence"
    SIZE_AND_STAGING_FEASIBILITY = "size_and_staging_feasibility"


GATE_ORDER: Final[tuple[CensusGate, ...]] = (
    CensusGate.RIGHTS_AND_TERMS,
    CensusGate.IMMUTABLE_VERSION_OR_AUTHORITY_IDENTIFIER,
    CensusGate.PHYSICAL_IDENTITY_AND_SYSTEM_FAMILY,
    CensusGate.OBJECT_CLASS_APPROPRIATE_EVIDENCE_PRESENCE,
    CensusGate.MECHANISM_AUTHORITY,
    CensusGate.PRE_OUTCOME_AMBIGUITY_AND_CHRONOLOGY,
    CensusGate.DIAGNOSTIC_ACTION_EXECUTION,
    CensusGate.RECOVERY_EXECUTION,
    CensusGate.INDEPENDENT_SETTLED_OUTCOME,
    CensusGate.CLOCK_CONTRACT,
    CensusGate.ROLE_INDEPENDENCE,
    CensusGate.SIZE_AND_STAGING_FEASIBILITY,
)


class GateStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    NOT_SCREENED = "not_screened"


class CensusVerdict(StrEnum):
    QUALIFYING_CANDIDATE = "CENSUS_QUALIFYING_CANDIDATE"
    NULL_WITHIN_FRAME = "CENSUS_NULL_WITHIN_FRAME"
    BLOCKED_RIGHTS = "CENSUS_BLOCKED_RIGHTS"
    INVALID = "CENSUS_INVALID"
    INFRASTRUCTURE_NULL = "CENSUS_INFRASTRUCTURE_NULL"


# A bounded frame cannot establish an unbounded negative. The legacy routing label is
# unreachable by this instrument and is rejected wherever a verdict is parsed.
UNREACHABLE_VERDICTS: Final[frozenset[str]] = frozenset({"KILL_PUBLIC_SUBSTRATE"})

STRATUM_B_DOMAINS: Final[tuple[str, ...]] = (
    "ntsb_public_investigation_dockets_all_modes",
    "us_chemical_safety_board_completed_investigations",
    "nrc_licensee_event_reports_and_information_notices",
    "nasa_lessons_learned_and_unrestricted_anomaly_reporting_surfaces",
    "gidep_alert_and_safe_alert_publications",
    "faa_service_difficulty_reports_and_airworthiness_directive_cited_material",
    "easa_and_esa_unrestricted_published_anomaly_and_safety_investigations",
    "osha_robotic_and_automated_machinery_accident_investigations",
    "doi_issuing_repositories_by_stated_query",
)


class SourceLocator(FrozenModel):
    kind: LocatorKind
    value: str = Field(min_length=1)


class SourceFactLocator(FrozenModel):
    """One factual assertion about a candidate, bound to exact retrieved bytes.

    A `mutable_page` fact can never establish a gate result. This is the frozen remedy for
    the legacy screen, whose blocking facts rest on pages the mission does not control and
    therefore cannot be re-checked by an independent auditor.
    """

    schema_version: Literal["inbar.iter001.source-fact-locator.v1"] = (
        "inbar.iter001.source-fact-locator.v1"
    )
    assertion_id: Identifier
    source_id: Identifier
    assertion_text: str = Field(min_length=1)
    retrieval_uri: str = Field(min_length=1)
    retrieval_method: str = Field(min_length=1)
    retrieved_at: datetime
    response_bytes_sha256: Sha256
    response_bytes: int = Field(ge=0)
    locator: SourceLocator
    excerpt_sha256: Sha256
    mutability_class: MutabilityClass
    frozen_identifier_kind: FrozenIdentifierKind | None = None
    frozen_identifier_value: str | None = None

    @model_validator(mode="after")
    def retrieval_time_is_aware(self) -> Self:
        if self.retrieved_at.tzinfo is None or self.retrieved_at.utcoffset() is None:
            raise ValueError("fact locator retrieval time must be timezone-aware")
        return self

    @model_validator(mode="after")
    def content_frozen_requires_authority_identifier(self) -> Self:
        frozen = self.mutability_class is MutabilityClass.CONTENT_FROZEN
        has_identifier = self.frozen_identifier_kind is not None and bool(
            self.frozen_identifier_value
        )
        if frozen and not has_identifier:
            raise ValueError(
                "a content_frozen fact requires an authority-issued immutable identifier"
            )
        if not frozen and has_identifier:
            raise ValueError("a mutable_page fact must not carry a frozen identifier")
        return self

    @property
    def gate_bearing_eligible(self) -> bool:
        return self.mutability_class is MutabilityClass.CONTENT_FROZEN


class ChronologyAssessment(FrozenModel):
    """Conditions C1-C6 for a historical record to satisfy pre-outcome ambiguity.

    All six are conjunctive. An exposed extraction (C6 false) is contaminated: it remains
    publishable as a diagnostic observation and is permanently ineligible for the
    thirty-incident floor. Counted historical dossiers therefore require a second,
    unexposed reviewer.
    """

    schema_version: Literal["inbar.iter001.census-chronology-assessment.v1"] = (
        "inbar.iter001.census-chronology-assessment.v1"
    )
    c1_hypothesis_artifact_content_frozen: bool
    c2_date_established_by_publishing_authority: bool
    c3_precedes_determination_artifact: bool
    c4_mechanism_set_stated_by_investigating_authority: bool
    c5_explicit_unknown_category_present: bool
    c6_extraction_reviewer_unexposed: bool
    hypothesis_artifact_locator: SourceFactLocator
    determination_artifact_locator: SourceFactLocator

    @model_validator(mode="after")
    def bound_artifacts_are_gate_bearing(self) -> Self:
        for name, locator in (
            ("hypothesis", self.hypothesis_artifact_locator),
            ("determination", self.determination_artifact_locator),
        ):
            if not locator.gate_bearing_eligible:
                raise ValueError(f"{name} artifact must be content_frozen to bear a gate")
        return self

    @model_validator(mode="after")
    def bound_artifacts_are_distinct(self) -> Self:
        # C3 is precedence by the publishing authority's own dating, which retrieval order
        # cannot establish and this contract therefore does not infer. What it can enforce
        # is that two distinct artifacts are bound: one artifact cannot both state the
        # hypothesis set and settle the determination it must precede.
        if (
            self.hypothesis_artifact_locator.response_bytes_sha256
            == self.determination_artifact_locator.response_bytes_sha256
        ):
            raise ValueError(
                "hypothesis and determination artifacts must be distinct bound artifacts"
            )
        return self

    @property
    def satisfied(self) -> bool:
        return all(
            (
                self.c1_hypothesis_artifact_content_frozen,
                self.c2_date_established_by_publishing_authority,
                self.c3_precedes_determination_artifact,
                self.c4_mechanism_set_stated_by_investigating_authority,
                self.c5_explicit_unknown_category_present,
                self.c6_extraction_reviewer_unexposed,
            )
        )

    @property
    def contaminated(self) -> bool:
        return not self.c6_extraction_reviewer_unexposed

    @property
    def floor_eligible(self) -> bool:
        return self.satisfied and not self.contaminated


class RoleInheritanceAssessment(FrozenModel):
    """Conditions I1-I4 for inheriting a producing authority's role separation.

    The frozen parent holds that organizational separation is supporting metadata and not
    proof by itself. These conditions do not weaken that; they define the narrow case in
    which inheritance is eligible at all.
    """

    schema_version: Literal["inbar.iter001.census-role-inheritance.v1"] = (
        "inbar.iter001.census-role-inheritance.v1"
    )
    i1_authority_governance_documents_role_separation: bool
    i2_record_names_distinct_role_holders: bool
    i3_conflict_record_constructible: bool
    i4_adjudicator_disjoint_from_operator_proposer_executor: bool
    governance_locator: SourceFactLocator

    @model_validator(mode="after")
    def governance_is_gate_bearing(self) -> Self:
        if not self.governance_locator.gate_bearing_eligible:
            raise ValueError("governance evidence must be content_frozen to bear a gate")
        return self

    @property
    def inherited(self) -> bool:
        return all(
            (
                self.i1_authority_governance_documents_role_separation,
                self.i2_record_names_distinct_role_holders,
                self.i3_conflict_record_constructible,
                self.i4_adjudicator_disjoint_from_operator_proposer_executor,
            )
        )


class GateResult(FrozenModel):
    schema_version: Literal["inbar.iter001.census-gate-result.v1"] = (
        "inbar.iter001.census-gate-result.v1"
    )
    gate: CensusGate
    status: GateStatus
    supporting_locators: tuple[SourceFactLocator, ...] = ()
    rationale: str = Field(min_length=1)

    @model_validator(mode="after")
    def decided_gate_rests_on_content_frozen_evidence(self) -> Self:
        if self.status is GateStatus.NOT_SCREENED:
            if self.supporting_locators:
                raise ValueError("an unscreened gate must bind no locator")
            return self
        if not self.supporting_locators:
            raise ValueError("a decided gate must bind at least one fact locator")
        if not any(locator.gate_bearing_eligible for locator in self.supporting_locators):
            raise ValueError(
                "a decided gate requires at least one content_frozen locator; "
                "a mutable_page fact is supporting context only"
            )
        return self


class CandidateScreening(FrozenModel):
    """One screened source candidate. Never a scientific unit."""

    schema_version: Literal["inbar.iter001.census-candidate-screening.v1"] = (
        "inbar.iter001.census-candidate-screening.v1"
    )
    source_id: Identifier
    domain_id: Identifier
    stratum: Stratum
    object_class: ObjectClass
    gate_results: tuple[GateResult, ...]
    chronology: ChronologyAssessment | None = None
    role_inheritance: RoleInheritanceAssessment | None = None

    @model_validator(mode="after")
    def gate_results_follow_frozen_order(self) -> Self:
        seen = tuple(result.gate for result in self.gate_results)
        if len(set(seen)) != len(seen):
            raise ValueError("a gate may appear at most once in a screening")
        expected = tuple(gate for gate in GATE_ORDER if gate in set(seen))
        if seen != expected:
            raise ValueError("gate results must follow the frozen cheapest-first order")
        return self

    @model_validator(mode="after")
    def screening_stops_at_first_failing_gate(self) -> Self:
        failed_index: int | None = None
        for index, result in enumerate(self.gate_results):
            if result.status is GateStatus.FAILED:
                failed_index = index
                break
        if failed_index is None:
            return self
        for result in self.gate_results[failed_index + 1 :]:
            if result.status is not GateStatus.NOT_SCREENED:
                raise ValueError(
                    "screening must stop at the first failing hard gate; "
                    "no later gate may be screened"
                )
        return self

    @property
    def passed(self) -> bool:
        decided = {result.gate: result.status for result in self.gate_results}
        return all(decided.get(gate) is GateStatus.PASSED for gate in GATE_ORDER)

    @property
    def first_failing_gate(self) -> CensusGate | None:
        for result in self.gate_results:
            if result.status is GateStatus.FAILED:
                return result.gate
        return None

    @property
    def evidential_weight(self) -> str:
        """Stratum A is contaminated: the drafter knew each claimed blocking gap.

        A stratum-A failure only reproduces that prior and is weak. A stratum-A pass
        contradicts it and is credible against contamination, and is published as a
        correction of the legacy screen.
        """
        if self.stratum is Stratum.PROSPECTIVE:
            return "prospective"
        return (
            "credible_against_prior_publish_as_legacy_correction"
            if self.passed
            else "weak_reproduces_prior"
        )


class CensusResourceUsage(FrozenModel):
    """Measured resources for one census audit.

    Amendment 002 freezes `missing_measurement_invalidates_audit`. This contract is therefore
    a required member of a census report: an unmeasured audit is invalid rather than
    unconstrained. Values are measured, never asserted; `measurement_method` names the
    primitive that produced them so a reader can tell a measurement from a guess.

    The amendment grants zero GPU, cloud, paid-provider, and cost authority. Those fields are
    typed to their only permitted value rather than left free, so an audit cannot record spend
    it was never authorized to make.
    """

    schema_version: Literal["inbar.iter001.census-resource-usage.v1"] = (
        "inbar.iter001.census-resource-usage.v1"
    )
    cpu_seconds: float = Field(ge=0)
    wall_seconds: float = Field(ge=0)
    peak_memory_bytes: int = Field(ge=0)
    retrieved_bytes: int = Field(ge=0)
    peak_staged_bytes: int = Field(ge=0)
    gpu_seconds: Literal[0] = 0
    cloud_jobs: Literal[0] = 0
    paid_calls: Literal[0] = 0
    cost_usd: Literal["0"] = "0"
    measurement_method: str = Field(min_length=1)
    measured_at: datetime

    @model_validator(mode="after")
    def measured_time_is_aware(self) -> Self:
        if self.measured_at.tzinfo is None or self.measured_at.utcoffset() is None:
            raise ValueError("census resource measurement time must be timezone-aware")
        return self

    @property
    def ceiling_breaches(self) -> tuple[str, ...]:
        breaches: list[str] = []
        if self.cpu_seconds > CEILING_CPU_SECONDS:
            breaches.append("cpu_seconds")
        if self.wall_seconds > CEILING_WALL_SECONDS:
            breaches.append("wall_seconds")
        if self.peak_memory_bytes > CEILING_PEAK_MEMORY_BYTES:
            breaches.append("peak_memory_bytes")
        if self.retrieved_bytes > CEILING_RETRIEVED_BYTES:
            breaches.append("retrieved_bytes")
        if self.peak_staged_bytes > CEILING_PEAK_STAGED_BYTES:
            breaches.append("peak_staged_bytes")
        return tuple(breaches)


@contextmanager
def measure_census_resources() -> Iterator[dict[str, float | int]]:
    """Measure real CPU, wall, and peak memory for a census audit.

    Uses only the standard library: `resource.getrusage` for CPU and peak resident memory
    across this process and its children, and `time.perf_counter` for wall time. The caller
    supplies retrieved and staged byte counts, which this primitive cannot observe.

    `ru_maxrss` is bytes on macOS and kibibytes on Linux; the platform difference is resolved
    explicitly rather than assumed, because a silent factor-of-1024 error would make the
    memory ceiling meaningless in exactly one direction.
    """
    started = time.perf_counter()
    before = resource.getrusage(resource.RUSAGE_SELF)
    before_children = resource.getrusage(resource.RUSAGE_CHILDREN)
    observed: dict[str, float | int] = {}
    try:
        yield observed
    finally:
        after = resource.getrusage(resource.RUSAGE_SELF)
        after_children = resource.getrusage(resource.RUSAGE_CHILDREN)
        cpu = (after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime)
        cpu += (after_children.ru_utime - before_children.ru_utime) + (
            after_children.ru_stime - before_children.ru_stime
        )
        scale = 1 if sys.platform == "darwin" else 1024
        observed["cpu_seconds"] = max(cpu, 0.0)
        observed["wall_seconds"] = max(time.perf_counter() - started, 0.0)
        observed["peak_memory_bytes"] = max(after.ru_maxrss, after_children.ru_maxrss) * scale


class CensusReport(FrozenModel):
    schema_version: Literal["inbar.iter001.census-report.v1"] = "inbar.iter001.census-report.v1"
    iteration_id: Literal["iter001_physical_causal_evidence_acquisition"]
    amendment_document_artifact_sha256: Sha256
    machine_proposal_artifact_sha256: Sha256
    owner_approval_receipt_hash: Sha256
    frame_scope: str = Field(min_length=1)
    frame_declared_incomplete: Literal[True]
    screenings: tuple[CandidateScreening, ...]
    verdict: CensusVerdict
    resource_usage: CensusResourceUsage
    produced_at: datetime

    @model_validator(mode="after")
    def binds_both_approved_artifact_hashes(self) -> Self:
        if self.amendment_document_artifact_sha256 != AMENDMENT_DOCUMENT_SHA256:
            raise ValueError("report does not bind the approved amendment document bytes")
        if self.machine_proposal_artifact_sha256 != MACHINE_PROPOSAL_SHA256:
            raise ValueError("report does not bind the approved machine proposal bytes")
        if self.owner_approval_receipt_hash != OWNER_APPROVAL_RECEIPT_HASH:
            raise ValueError("report does not bind the owner-approval receipt")
        return self

    @model_validator(mode="after")
    def produced_time_is_aware(self) -> Self:
        if self.produced_at.tzinfo is None or self.produced_at.utcoffset() is None:
            raise ValueError("census report time must be timezone-aware")
        return self

    @model_validator(mode="after")
    def source_ids_are_unique(self) -> Self:
        ids = [screening.source_id for screening in self.screenings]
        if len(set(ids)) != len(ids):
            raise ValueError("a source may be screened at most once per census")
        return self

    @model_validator(mode="after")
    def verdict_follows_from_screenings(self) -> Self:
        any_passed = any(screening.passed for screening in self.screenings)
        if self.verdict is CensusVerdict.QUALIFYING_CANDIDATE and not any_passed:
            raise ValueError("a qualifying verdict requires at least one passing candidate")
        if self.verdict is CensusVerdict.NULL_WITHIN_FRAME and any_passed:
            raise ValueError("a null verdict is invalid when a candidate passed every gate")
        return self

    @property
    def nominations(self) -> tuple[Identifier, ...]:
        """Passing candidates are nominated for separately authorized acquisition.

        A nomination admits nothing, counts nothing, and asserts no incident.
        """
        return tuple(screening.source_id for screening in self.screenings if screening.passed)


def census_subject_hash(kind: str, subject: object) -> str:
    return sha256_value(
        {
            "domain": "inbar.iter001.census-subject.v1",
            "kind": kind,
            "subject": subject,
        }
    )


def reject_unreachable_verdict(verdict: str) -> None:
    """A bounded frame cannot establish an unbounded negative."""
    if verdict in UNREACHABLE_VERDICTS:
        raise CensusError(
            f"{verdict} is not reachable by the census instrument; "
            "a bounded frame cannot establish an unbounded negative"
        )


def assert_no_field_borrowing(
    screening: CandidateScreening, *, locator_source_ids: frozenset[str]
) -> None:
    """A missing construct field is never supplied by another candidate.

    Every locator bound by a screening must name that screening's own source.
    """
    foreign = locator_source_ids - {screening.source_id}
    if foreign:
        raise CensusError(
            f"candidate {screening.source_id} borrows evidence from {sorted(foreign)}; "
            "a missing construct field cannot be supplied by another candidate"
        )


def verify_census_report(report: CensusReport) -> CensusReport:
    """Recompute the fail-closed invariants a census report must satisfy."""
    reject_unreachable_verdict(report.verdict.value)
    breaches = report.resource_usage.ceiling_breaches
    if breaches:
        raise CensusError(
            "census audit exceeded its frozen resource ceiling: " + ", ".join(breaches)
        )
    for screening in report.screenings:
        locator_sources = frozenset(
            locator.source_id
            for result in screening.gate_results
            for locator in result.supporting_locators
        )
        assert_no_field_borrowing(screening, locator_source_ids=locator_sources)
        if (
            screening.chronology is not None
            and screening.chronology.contaminated
            and screening.passed
        ):
            raise CensusError(
                f"candidate {screening.source_id} has a contaminated extraction and "
                "is permanently ineligible for the incident floor; it cannot pass"
            )
    if report.produced_at > datetime.now(UTC):
        raise CensusError("census report is dated in the future")
    return report


# --- Owner-approval authority verification ------------------------------------------
#
# Amendment 001's approval has a committed verifier; without the block below, Amendment 002's
# approval would rest on prose plus a hash constant, which is exactly the unreconstructible
# authority this mission rejects. The owner identity, anchor, and public key are imported from
# the Amendment 001 contract module so the two approvals provably share one trust root.

PREVIOUS_APPROVAL_PATH: Final = AMENDMENT_001_RECEIPT_PATH
APPROVAL_GENESIS: Final = "0" * 64
CENSUS_DECISION_LITERAL = Literal["approve_source_census_implementation_only"]
_MAX_AUTHORITY_FILE_BYTES: Final = 2 * 1024 * 1024
_GIT_OBJECT_ID: Final = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
CENSUS_DENIED_AUTHORITIES: Final = (
    "retrieval",
    "census_execution",
    "corpus_acquisition",
    "resource_spend",
    "physical_action",
    "training",
    "scientific_result",
    "canonical_seal",
    "publication_transition",
)


class OwnerCensusApprovalReceipt(FrozenModel):
    """The Amendment 002 owner approval.

    Schema v2 widens the frozen decision literal only; every other field, the hash rule, and
    the signature rule are byte-identical in construction to v1. A v1 receipt is never
    reinterpreted under this model.
    """

    schema_version: Literal["inbar.owner-amendment-approval-receipt.v2"]
    approval_id: Identifier
    owner_actor_id: Identifier
    owner_signing_key_id: Identifier
    owner_signer_anchor_artifact_sha256: Sha256
    owner_key_trust_basis: str = Field(min_length=1)
    owner_ed25519_public_key: Ed25519PublicKey
    proposal_git_commit: GitObjectId
    amendment_document_artifact_sha256: Sha256
    machine_proposal_artifact_sha256: Sha256
    decision: CENSUS_DECISION_LITERAL
    previous_approval_receipt_sha256: Sha256
    nonce: Sha256
    issued_at: datetime
    receipt_hash: Sha256
    signature: HexSignature

    @model_validator(mode="after")
    def issued_time_is_aware(self) -> Self:
        if self.issued_at.tzinfo is None or self.issued_at.utcoffset() is None:
            raise ValueError("owner approval timestamp must be timezone-aware")
        return self

    @model_validator(mode="after")
    def receipt_hash_is_derived(self) -> Self:
        if sha256_value(census_owner_approval_body(self)) != self.receipt_hash:
            raise ValueError("owner approval receipt hash mismatch")
        return self


class CensusImplementationAuthorityVerification(FrozenModel):
    """Non-portable report returned by a fresh repository verification.

    This model is not authorization evidence and must never be accepted as a gate input.
    A consumer crossing a trust boundary must call
    :func:`load_census_implementation_authority` against its own repository.
    """

    schema_version: Literal["inbar.verified-census-implementation-authority.v1"] = (
        "inbar.verified-census-implementation-authority.v1"
    )
    proposal_git_commit: GitObjectId
    amendment_document_artifact_sha256: Sha256
    machine_proposal_artifact_sha256: Sha256
    owner_approval_receipt_artifact_sha256: Sha256
    owner_approval_receipt_hash: Sha256
    previous_approval_receipt_hash: Sha256
    authorized_action: Literal["source_census_implementation_only"] = (
        "source_census_implementation_only"
    )
    denied_authorities: tuple[str, ...] = CENSUS_DENIED_AUTHORITIES
    verified_at: datetime


def census_owner_approval_body(
    receipt: OwnerCensusApprovalReceipt | dict[str, Any],
) -> dict[str, Any]:
    body = (
        receipt.model_dump(mode="json")
        if isinstance(receipt, OwnerCensusApprovalReceipt)
        else dict(receipt)
    )
    body.pop("receipt_hash", None)
    body.pop("signature", None)
    return body


def _read_regular_file(path: Path, label: str) -> bytes:
    try:
        file_stat = path.lstat()
    except OSError as error:
        raise CensusError(f"{label} is unavailable") from error
    if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
        raise CensusError(f"{label} must be a regular file")
    if file_stat.st_size > _MAX_AUTHORITY_FILE_BYTES:
        raise CensusError(f"{label} exceeds its byte limit")
    try:
        data = path.read_bytes()
    except OSError as error:
        raise CensusError(f"{label} cannot be read") from error
    if len(data) != file_stat.st_size:
        raise CensusError(f"{label} changed while being read")
    return data


def _canonical_json_object(
    data: bytes,
    label: str,
    *,
    require_pretty: bool = True,
) -> dict[str, Any]:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise CensusError(f"{label} contains duplicate object keys")
            value[key] = item
        return value

    try:
        parsed = json.loads(data, object_pairs_hook=object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CensusError(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(parsed, dict):
        raise CensusError(f"{label} must be a JSON object")
    if require_pretty and canonical_json_pretty(parsed) != data:
        raise CensusError(f"{label} is not canonical pretty JSON")
    return parsed


def _git_blob(repo_root: Path, commit: str, relative: str, label: str) -> bytes:
    git = str(trusted_git_executable())
    try:
        completed = subprocess.run(  # noqa: S603 - fixed Git object read
            [git, "show", f"{commit}:{relative}"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            env=git_environment(),
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CensusError(f"committed {label} is unavailable") from error
    if len(completed.stdout) > _MAX_AUTHORITY_FILE_BYTES:
        raise CensusError(f"committed {label} exceeds its byte limit")
    return completed.stdout


def _verify_census_git_history(repo_root: Path) -> str:
    git = str(trusted_git_executable())
    environment = git_environment()
    try:
        verify_repository_trust(repo_root, git)
    except GitTrustError as error:
        raise CensusError(f"authority Git trust failed: {error}") from error
    try:
        head_result = subprocess.run(  # noqa: S603 - fixed Git identity query
            [git, "rev-parse", "--verify", "HEAD^{commit}"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            env=environment,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CensusError("authority Git HEAD cannot be verified") from error
    head = head_result.stdout.strip()
    if _GIT_OBJECT_ID.fullmatch(head) is None:
        raise CensusError("authority Git HEAD has an invalid object identity")
    for ancestor in (OWNER_ANCHOR_COMMIT, APPROVED_PROPOSAL_COMMIT):
        try:
            completed = subprocess.run(  # noqa: S603 - fixed Git ancestry query
                [git, "merge-base", "--is-ancestor", ancestor, head],
                cwd=repo_root,
                check=False,
                capture_output=True,
                env=environment,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise CensusError("approved Git ancestry cannot be verified") from error
        if completed.returncode != 0:
            raise CensusError("approved Git history is not an ancestor of HEAD")
    return head


def _verify_census_receipt_scope_and_signature(receipt: OwnerCensusApprovalReceipt) -> None:
    expected = {
        "owner_actor_id": OWNER_ACTOR_ID,
        "owner_signing_key_id": OWNER_SIGNING_KEY_ID,
        "owner_signer_anchor_artifact_sha256": OWNER_ANCHOR_SHA256,
        "owner_key_trust_basis": OWNER_TRUST_BASIS,
        "owner_ed25519_public_key": OWNER_PUBLIC_KEY,
        "proposal_git_commit": APPROVED_PROPOSAL_COMMIT,
        "amendment_document_artifact_sha256": AMENDMENT_DOCUMENT_SHA256,
        "machine_proposal_artifact_sha256": MACHINE_PROPOSAL_SHA256,
        "decision": CENSUS_DECISION,
        "previous_approval_receipt_sha256": PREVIOUS_APPROVAL_RECEIPT_HASH,
    }
    observed = receipt.model_dump(mode="json")
    if any(observed[field] != value for field, value in expected.items()):
        raise CensusError("owner approval differs from the approved census scope")
    if receipt.previous_approval_receipt_sha256 == APPROVAL_GENESIS:
        raise CensusError("census approval must chain to a predecessor, not genesis")
    try:
        VerifyKey(bytes.fromhex(OWNER_PUBLIC_KEY)).verify(
            bytes.fromhex(receipt.receipt_hash), bytes.fromhex(receipt.signature)
        )
    except (BadSignatureError, ValueError) as error:
        raise CensusError("owner approval signature mismatch") from error


def _verify_census_proposal_chain_and_anchor(
    repo_root: Path,
    head: str,
    receipt: OwnerCensusApprovalReceipt,
) -> None:
    amendment = _git_blob(
        repo_root, APPROVED_PROPOSAL_COMMIT, AMENDMENT_DOCUMENT_PATH, "amendment document"
    )
    machine = _git_blob(
        repo_root, APPROVED_PROPOSAL_COMMIT, MACHINE_PROPOSAL_PATH, "machine proposal"
    )
    anchor = _git_blob(repo_root, OWNER_ANCHOR_COMMIT, OWNER_ANCHOR_PATH, "owner anchor")
    if hashlib.sha256(amendment).hexdigest() != AMENDMENT_DOCUMENT_SHA256:
        raise CensusError("committed amendment document hash mismatch")
    if hashlib.sha256(machine).hexdigest() != MACHINE_PROPOSAL_SHA256:
        raise CensusError("committed machine proposal hash mismatch")
    if hashlib.sha256(anchor).hexdigest() != OWNER_ANCHOR_SHA256:
        raise CensusError("committed owner anchor hash mismatch")
    # The machine proposal's raw bytes are frozen by the owner's signature and are not
    # canonical pretty JSON; it is bound as a grandfathered raw-byte artifact exactly as the
    # Amendment 001 hash-modes section defines. Duplicate keys are still rejected.
    machine_value = _canonical_json_object(machine, "machine proposal", require_pretty=False)
    anchor_value = _canonical_json_object(anchor, "owner anchor", require_pretty=False)
    if machine_value.get("amendment_document") != {
        "artifact_sha256": receipt.amendment_document_artifact_sha256,
        "path": AMENDMENT_DOCUMENT_PATH,
    }:
        raise CensusError("machine proposal does not bind the amendment document")
    if anchor_value.get("trust_anchor_public_key") != OWNER_PUBLIC_KEY:
        raise CensusError("owner anchor does not bind the approved public key")
    # The chain predecessor is verified against the committed Amendment 001 receipt itself,
    # not against a constant: the prior receipt is read at HEAD, parsed strictly under its
    # own v1 model, and its derived hash must equal this receipt's declared predecessor.
    previous_raw = _git_blob(repo_root, head, PREVIOUS_APPROVAL_PATH, "predecessor receipt")
    try:
        previous = OwnerAmendmentApprovalReceipt.model_validate_json(previous_raw, strict=True)
    except ValueError as error:
        raise CensusError("predecessor approval receipt violates its typed contract") from error
    if previous.receipt_hash != receipt.previous_approval_receipt_sha256:
        raise CensusError("census approval does not chain to the committed predecessor")


def load_census_implementation_authority(
    repo_root: Path,
    *,
    verified_at: datetime | None = None,
) -> CensusImplementationAuthorityVerification:
    """Reconstruct the Amendment 002 implementation authority from committed bytes.

    Mirrors the Amendment 001 verifier: nothing here trusts a constant that the committed
    artifacts cannot corroborate, and any Git, byte, scope, chain, or signature mismatch
    fails closed.
    """
    root = repo_root.resolve(strict=True)
    head = _verify_census_git_history(root)
    receipt_path = root / OWNER_APPROVAL_PATH
    raw_receipt = _read_regular_file(receipt_path, "owner approval receipt")
    _canonical_json_object(raw_receipt, "owner approval receipt")
    try:
        receipt = OwnerCensusApprovalReceipt.model_validate_json(raw_receipt, strict=True)
    except ValueError as error:
        raise CensusError("owner approval receipt violates its typed contract") from error
    head_receipt = _git_blob(root, head, OWNER_APPROVAL_PATH, "owner approval receipt")
    if head_receipt != raw_receipt:
        raise CensusError("owner approval receipt is not committed at HEAD")
    _verify_census_proposal_chain_and_anchor(root, head, receipt)
    _verify_census_receipt_scope_and_signature(receipt)
    if _verify_census_git_history(root) != head:
        raise CensusError("authority Git HEAD changed during verification")

    checked_at = verified_at or datetime.now(UTC)
    if checked_at.tzinfo is None or checked_at.utcoffset() is None:
        raise CensusError("authority verification time must be timezone-aware")
    if checked_at < receipt.issued_at:
        raise CensusError("authority verification predates owner approval")
    return CensusImplementationAuthorityVerification(
        proposal_git_commit=receipt.proposal_git_commit,
        amendment_document_artifact_sha256=receipt.amendment_document_artifact_sha256,
        machine_proposal_artifact_sha256=receipt.machine_proposal_artifact_sha256,
        owner_approval_receipt_artifact_sha256=hashlib.sha256(raw_receipt).hexdigest(),
        owner_approval_receipt_hash=receipt.receipt_hash,
        previous_approval_receipt_hash=receipt.previous_approval_receipt_sha256,
        verified_at=checked_at,
    )
