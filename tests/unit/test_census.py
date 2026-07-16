"""Adversarial control suite for the Iteration 001 source-screening census.

Every control below is required by Amendment 002. A validator without negative fixtures is
paper-only review and is not a gate.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from fieldtrue.census import (
    AMENDMENT_DOCUMENT_SHA256,
    CEILING_CPU_SECONDS,
    CEILING_PEAK_MEMORY_BYTES,
    CEILING_PEAK_STAGED_BYTES,
    CEILING_RETRIEVED_BYTES,
    CEILING_WALL_SECONDS,
    GATE_ORDER,
    MACHINE_PROPOSAL_SHA256,
    OWNER_APPROVAL_RECEIPT_HASH,
    STRATUM_B_DOMAINS,
    CandidateScreening,
    CensusError,
    CensusGate,
    CensusReport,
    CensusResourceUsage,
    CensusVerdict,
    ChronologyAssessment,
    FrozenIdentifierKind,
    GateResult,
    GateStatus,
    LocatorKind,
    MutabilityClass,
    ObjectClass,
    RoleInheritanceAssessment,
    SourceFactLocator,
    SourceLocator,
    Stratum,
    census_subject_hash,
    measure_census_resources,
    reject_unreachable_verdict,
    verify_census_report,
)

NOW = datetime(2026, 7, 16, 12, 0, 0, tzinfo=UTC)


def _locator(
    *,
    source_id: str = "ntsb-docket-example",
    assertion_id: str = "assertion-001",
    mutability: MutabilityClass = MutabilityClass.CONTENT_FROZEN,
    digest: str = "a" * 64,
) -> SourceFactLocator:
    frozen = mutability is MutabilityClass.CONTENT_FROZEN
    return SourceFactLocator(
        assertion_id=assertion_id,
        source_id=source_id,
        assertion_text="The record states the competing mechanisms before determination.",
        retrieval_uri="https://example.invalid/docket/1",
        retrieval_method="https-get",
        retrieved_at=NOW,
        response_bytes_sha256=digest,
        response_bytes=1024,
        locator=SourceLocator(kind=LocatorKind.PDF_PAGE, value="12"),
        excerpt_sha256="b" * 64,
        mutability_class=mutability,
        frozen_identifier_kind=(
            FrozenIdentifierKind.AUTHORITY_ASSIGNED_DOCKET_OR_REPORT_NUMBER if frozen else None
        ),
        frozen_identifier_value="DCA26MA001" if frozen else None,
    )


def _passing_gates(source_id: str = "ntsb-docket-example") -> tuple[GateResult, ...]:
    return tuple(
        GateResult(
            gate=gate,
            status=GateStatus.PASSED,
            supporting_locators=(_locator(source_id=source_id, assertion_id=f"a-{gate.value}"),),
            rationale=f"{gate.value} established from a content-frozen authority artifact.",
        )
        for gate in GATE_ORDER
    )


def _usage(**overrides: object) -> CensusResourceUsage:
    values: dict[str, object] = {
        "cpu_seconds": 12.5,
        "wall_seconds": 30.0,
        "peak_memory_bytes": 256 * 1024**2,
        "retrieved_bytes": 4 * 1024**2,
        "peak_staged_bytes": 8 * 1024**2,
        "measurement_method": "resource.getrusage+time.perf_counter",
        "measured_at": NOW,
    }
    values.update(overrides)
    return CensusResourceUsage(**values)  # type: ignore[arg-type]


def _report(screenings: tuple[CandidateScreening, ...], verdict: CensusVerdict) -> CensusReport:
    return CensusReport(
        iteration_id="iter001_physical_causal_evidence_acquisition",
        amendment_document_artifact_sha256=AMENDMENT_DOCUMENT_SHA256,
        machine_proposal_artifact_sha256=MACHINE_PROPOSAL_SHA256,
        owner_approval_receipt_hash=OWNER_APPROVAL_RECEIPT_HASH,
        frame_scope="stratum_a_legacy_sixteen_plus_stratum_b_enumerated_investigation_domains",
        frame_declared_incomplete=True,
        screenings=screenings,
        verdict=verdict,
        resource_usage=_usage(),
        produced_at=NOW,
    )


# --- Positive controls -------------------------------------------------------------


def test_synthetic_candidate_passing_every_gate_is_the_evaluator_positive_control() -> None:
    screening = CandidateScreening(
        source_id="ntsb-docket-example",
        domain_id="ntsb_public_investigation_dockets_all_modes",
        stratum=Stratum.PROSPECTIVE,
        object_class=ObjectClass.INVESTIGATION_RECORD,
        gate_results=_passing_gates(),
    )
    assert screening.passed is True
    assert screening.first_failing_gate is None
    report = verify_census_report(_report((screening,), CensusVerdict.QUALIFYING_CANDIDATE))
    assert report.nominations == ("ntsb-docket-example",)


def test_candidate_failing_exactly_one_gate_is_the_conjunctivity_control() -> None:
    results: list[GateResult] = []
    for gate in GATE_ORDER:
        if gate is CensusGate.RECOVERY_EXECUTION:
            results.append(
                GateResult(
                    gate=gate,
                    status=GateStatus.FAILED,
                    supporting_locators=(_locator(),),
                    rationale="No recovery was executed; the record ends at determination.",
                )
            )
        elif GATE_ORDER.index(gate) > GATE_ORDER.index(CensusGate.RECOVERY_EXECUTION):
            results.append(
                GateResult(gate=gate, status=GateStatus.NOT_SCREENED, rationale="Stopped earlier.")
            )
        else:
            results.append(
                GateResult(
                    gate=gate,
                    status=GateStatus.PASSED,
                    supporting_locators=(_locator(assertion_id=f"a-{gate.value}"),),
                    rationale="Established.",
                )
            )
    screening = CandidateScreening(
        source_id="ntsb-docket-example",
        domain_id="ntsb_public_investigation_dockets_all_modes",
        stratum=Stratum.PROSPECTIVE,
        object_class=ObjectClass.INVESTIGATION_RECORD,
        gate_results=tuple(results),
    )
    assert screening.passed is False
    assert screening.first_failing_gate is CensusGate.RECOVERY_EXECUTION
    verify_census_report(_report((screening,), CensusVerdict.NULL_WITHIN_FRAME))


# --- Fact-locator controls ---------------------------------------------------------


@pytest.mark.parametrize("gate", list(GATE_ORDER))
def test_mutable_page_cannot_establish_any_gate(gate: CensusGate) -> None:
    with pytest.raises(ValidationError, match="content_frozen"):
        GateResult(
            gate=gate,
            status=GateStatus.PASSED,
            supporting_locators=(_locator(mutability=MutabilityClass.MUTABLE_PAGE),),
            rationale="Claimed from a page the mission does not control.",
        )


def test_content_frozen_requires_authority_issued_immutable_identifier() -> None:
    with pytest.raises(ValidationError, match="authority-issued immutable identifier"):
        SourceFactLocator(
            assertion_id="assertion-001",
            source_id="src",
            assertion_text="claim",
            retrieval_uri="https://example.invalid/x",
            retrieval_method="https-get",
            retrieved_at=NOW,
            response_bytes_sha256="a" * 64,
            response_bytes=10,
            locator=SourceLocator(kind=LocatorKind.SECTION_PATH, value="/a/b"),
            excerpt_sha256="b" * 64,
            mutability_class=MutabilityClass.CONTENT_FROZEN,
        )


def test_mutable_page_must_not_carry_a_frozen_identifier() -> None:
    with pytest.raises(ValidationError, match="must not carry a frozen identifier"):
        SourceFactLocator(
            assertion_id="assertion-001",
            source_id="src",
            assertion_text="claim",
            retrieval_uri="https://example.invalid/x",
            retrieval_method="https-get",
            retrieved_at=NOW,
            response_bytes_sha256="a" * 64,
            response_bytes=10,
            locator=SourceLocator(kind=LocatorKind.SECTION_PATH, value="/a/b"),
            excerpt_sha256="b" * 64,
            mutability_class=MutabilityClass.MUTABLE_PAGE,
            frozen_identifier_kind=FrozenIdentifierKind.DOI,
            frozen_identifier_value="10.0000/x",
        )


def test_naive_retrieval_time_is_rejected() -> None:
    with pytest.raises(ValidationError):
        SourceFactLocator(
            assertion_id="assertion-001",
            source_id="src",
            assertion_text="claim",
            retrieval_uri="https://example.invalid/x",
            retrieval_method="https-get",
            retrieved_at=datetime(2026, 7, 16, 12, 0, 0),  # noqa: DTZ001
            response_bytes_sha256="a" * 64,
            response_bytes=10,
            locator=SourceLocator(kind=LocatorKind.SECTION_PATH, value="/a/b"),
            excerpt_sha256="b" * 64,
            mutability_class=MutabilityClass.MUTABLE_PAGE,
        )


def test_decided_gate_must_bind_at_least_one_locator() -> None:
    with pytest.raises(ValidationError, match="must bind at least one fact locator"):
        GateResult(
            gate=CensusGate.RIGHTS_AND_TERMS,
            status=GateStatus.PASSED,
            supporting_locators=(),
            rationale="Asserted with no evidence.",
        )


def test_unscreened_gate_must_bind_no_locator() -> None:
    with pytest.raises(ValidationError, match="must bind no locator"):
        GateResult(
            gate=CensusGate.RIGHTS_AND_TERMS,
            status=GateStatus.NOT_SCREENED,
            supporting_locators=(_locator(),),
            rationale="Not screened but evidence attached.",
        )


# --- Gate-order and stop-rule controls ---------------------------------------------


def test_gate_order_violation_is_rejected() -> None:
    reversed_two = (
        GateResult(
            gate=CensusGate.IMMUTABLE_VERSION_OR_AUTHORITY_IDENTIFIER,
            status=GateStatus.PASSED,
            supporting_locators=(_locator(assertion_id="a-1"),),
            rationale="Out of order.",
        ),
        GateResult(
            gate=CensusGate.RIGHTS_AND_TERMS,
            status=GateStatus.PASSED,
            supporting_locators=(_locator(assertion_id="a-2"),),
            rationale="Out of order.",
        ),
    )
    with pytest.raises(ValidationError, match="cheapest-first order"):
        CandidateScreening(
            source_id="src",
            domain_id="d",
            stratum=Stratum.PROSPECTIVE,
            object_class=ObjectClass.DATASET_RELEASE,
            gate_results=reversed_two,
        )


def test_duplicate_gate_in_one_screening_is_rejected() -> None:
    duplicated = (
        GateResult(
            gate=CensusGate.RIGHTS_AND_TERMS,
            status=GateStatus.PASSED,
            supporting_locators=(_locator(assertion_id="a-1"),),
            rationale="First.",
        ),
        GateResult(
            gate=CensusGate.RIGHTS_AND_TERMS,
            status=GateStatus.PASSED,
            supporting_locators=(_locator(assertion_id="a-2"),),
            rationale="Duplicate.",
        ),
    )
    with pytest.raises(ValidationError, match="at most once"):
        CandidateScreening(
            source_id="src",
            domain_id="d",
            stratum=Stratum.PROSPECTIVE,
            object_class=ObjectClass.DATASET_RELEASE,
            gate_results=duplicated,
        )


def test_screening_after_a_failing_hard_gate_is_rejected() -> None:
    kept = (
        GateResult(
            gate=CensusGate.RIGHTS_AND_TERMS,
            status=GateStatus.FAILED,
            supporting_locators=(_locator(assertion_id="a-1"),),
            rationale="Noncommercial terms.",
        ),
        GateResult(
            gate=CensusGate.IMMUTABLE_VERSION_OR_AUTHORITY_IDENTIFIER,
            status=GateStatus.PASSED,
            supporting_locators=(_locator(assertion_id="a-2"),),
            rationale="Screened anyway, which the stop rule forbids.",
        ),
    )
    with pytest.raises(ValidationError, match="stop at the first failing hard gate"):
        CandidateScreening(
            source_id="src",
            domain_id="d",
            stratum=Stratum.PROSPECTIVE,
            object_class=ObjectClass.DATASET_RELEASE,
            gate_results=kept,
        )


# --- No-borrowing control ----------------------------------------------------------


def test_candidate_cannot_borrow_a_field_from_another_candidate() -> None:
    borrowed = tuple(
        GateResult(
            gate=gate,
            status=GateStatus.PASSED,
            supporting_locators=(
                _locator(
                    source_id=("other-source" if gate is CensusGate.MECHANISM_AUTHORITY else "src"),
                    assertion_id=f"a-{gate.value}",
                ),
            ),
            rationale="Established.",
        )
        for gate in GATE_ORDER
    )
    screening = CandidateScreening(
        source_id="src",
        domain_id="d",
        stratum=Stratum.PROSPECTIVE,
        object_class=ObjectClass.INVESTIGATION_RECORD,
        gate_results=borrowed,
    )
    with pytest.raises(CensusError, match="borrows evidence from"):
        verify_census_report(_report((screening,), CensusVerdict.QUALIFYING_CANDIDATE))


# --- Chronology controls (C1-C6) ---------------------------------------------------


def _chronology(**overrides: bool) -> ChronologyAssessment:
    values: dict[str, bool] = {
        "c1_hypothesis_artifact_content_frozen": True,
        "c2_date_established_by_publishing_authority": True,
        "c3_precedes_determination_artifact": True,
        "c4_mechanism_set_stated_by_investigating_authority": True,
        "c5_explicit_unknown_category_present": True,
        "c6_extraction_reviewer_unexposed": True,
    }
    values.update(overrides)
    return ChronologyAssessment(
        **values,
        hypothesis_artifact_locator=_locator(assertion_id="hyp", digest="c" * 64),
        determination_artifact_locator=_locator(assertion_id="det", digest="d" * 64),
    )


def test_all_six_chronology_conditions_are_conjunctive() -> None:
    assert _chronology().satisfied is True
    for condition in (
        "c1_hypothesis_artifact_content_frozen",
        "c2_date_established_by_publishing_authority",
        "c3_precedes_determination_artifact",
        "c4_mechanism_set_stated_by_investigating_authority",
        "c5_explicit_unknown_category_present",
        "c6_extraction_reviewer_unexposed",
    ):
        assert _chronology(**{condition: False}).satisfied is False, condition


def test_researcher_reconstructed_hypothesis_set_fails_c4() -> None:
    assert _chronology(c4_mechanism_set_stated_by_investigating_authority=False).satisfied is False


def test_manufactured_unknown_category_fails_c5() -> None:
    assert _chronology(c5_explicit_unknown_category_present=False).satisfied is False


def test_exposed_extraction_is_contaminated_and_floor_ineligible() -> None:
    exposed = _chronology(c6_extraction_reviewer_unexposed=False)
    assert exposed.contaminated is True
    assert exposed.floor_eligible is False


def test_unexposed_extraction_is_floor_eligible() -> None:
    assert _chronology().floor_eligible is True


def test_contaminated_extraction_cannot_pass_the_census() -> None:
    screening = CandidateScreening(
        source_id="ntsb-docket-example",
        domain_id="ntsb_public_investigation_dockets_all_modes",
        stratum=Stratum.PROSPECTIVE,
        object_class=ObjectClass.INVESTIGATION_RECORD,
        gate_results=_passing_gates(),
        chronology=_chronology(c6_extraction_reviewer_unexposed=False),
    )
    with pytest.raises(CensusError, match="contaminated extraction"):
        verify_census_report(_report((screening,), CensusVerdict.QUALIFYING_CANDIDATE))


def test_hypothesis_and_determination_must_be_distinct_artifacts() -> None:
    with pytest.raises(ValidationError, match="distinct bound artifacts"):
        ChronologyAssessment(
            c1_hypothesis_artifact_content_frozen=True,
            c2_date_established_by_publishing_authority=True,
            c3_precedes_determination_artifact=True,
            c4_mechanism_set_stated_by_investigating_authority=True,
            c5_explicit_unknown_category_present=True,
            c6_extraction_reviewer_unexposed=True,
            hypothesis_artifact_locator=_locator(assertion_id="hyp", digest="e" * 64),
            determination_artifact_locator=_locator(assertion_id="det", digest="e" * 64),
        )


def test_chronology_artifacts_must_be_content_frozen() -> None:
    with pytest.raises(ValidationError, match="content_frozen"):
        ChronologyAssessment(
            c1_hypothesis_artifact_content_frozen=True,
            c2_date_established_by_publishing_authority=True,
            c3_precedes_determination_artifact=True,
            c4_mechanism_set_stated_by_investigating_authority=True,
            c5_explicit_unknown_category_present=True,
            c6_extraction_reviewer_unexposed=True,
            hypothesis_artifact_locator=_locator(
                assertion_id="hyp", mutability=MutabilityClass.MUTABLE_PAGE, digest="c" * 64
            ),
            determination_artifact_locator=_locator(assertion_id="det", digest="d" * 64),
        )


# --- Role-inheritance controls (I1-I4) ---------------------------------------------


def _roles(**overrides: bool) -> RoleInheritanceAssessment:
    values: dict[str, bool] = {
        "i1_authority_governance_documents_role_separation": True,
        "i2_record_names_distinct_role_holders": True,
        "i3_conflict_record_constructible": True,
        "i4_adjudicator_disjoint_from_operator_proposer_executor": True,
    }
    values.update(overrides)
    return RoleInheritanceAssessment(**values, governance_locator=_locator(assertion_id="gov"))


def test_all_four_role_inheritance_conditions_are_conjunctive() -> None:
    assert _roles().inherited is True
    for condition in (
        "i1_authority_governance_documents_role_separation",
        "i2_record_names_distinct_role_holders",
        "i3_conflict_record_constructible",
        "i4_adjudicator_disjoint_from_operator_proposer_executor",
    ):
        assert _roles(**{condition: False}).inherited is False, condition


def test_organizational_separation_without_governance_documentation_establishes_nothing() -> None:
    assert _roles(i1_authority_governance_documents_role_separation=False).inherited is False


def test_role_governance_evidence_must_be_content_frozen() -> None:
    with pytest.raises(ValidationError, match="content_frozen"):
        RoleInheritanceAssessment(
            i1_authority_governance_documents_role_separation=True,
            i2_record_names_distinct_role_holders=True,
            i3_conflict_record_constructible=True,
            i4_adjudicator_disjoint_from_operator_proposer_executor=True,
            governance_locator=_locator(
                assertion_id="gov", mutability=MutabilityClass.MUTABLE_PAGE
            ),
        )


# --- Stratum controls --------------------------------------------------------------


def test_stratum_a_failure_is_weak_and_stratum_a_pass_is_a_legacy_correction() -> None:
    failing = (
        GateResult(
            gate=CensusGate.RIGHTS_AND_TERMS,
            status=GateStatus.FAILED,
            supporting_locators=(_locator(source_id="alfa"),),
            rationale="Reproduces the known prior.",
        ),
        *[
            GateResult(gate=gate, status=GateStatus.NOT_SCREENED, rationale="Stopped.")
            for gate in GATE_ORDER[1:]
        ],
    )
    weak = CandidateScreening(
        source_id="alfa",
        domain_id="legacy",
        stratum=Stratum.PRIOR_EXPOSED,
        object_class=ObjectClass.DATASET_RELEASE,
        gate_results=failing,
    )
    assert weak.evidential_weight == "weak_reproduces_prior"

    correction = CandidateScreening(
        source_id="alfa",
        domain_id="legacy",
        stratum=Stratum.PRIOR_EXPOSED,
        object_class=ObjectClass.DATASET_RELEASE,
        gate_results=_passing_gates(source_id="alfa"),
    )
    assert correction.evidential_weight == "credible_against_prior_publish_as_legacy_correction"


def test_prospective_stratum_is_not_weighted_against_a_prior() -> None:
    screening = CandidateScreening(
        source_id="ntsb-docket-example",
        domain_id="ntsb_public_investigation_dockets_all_modes",
        stratum=Stratum.PROSPECTIVE,
        object_class=ObjectClass.INVESTIGATION_RECORD,
        gate_results=_passing_gates(),
    )
    assert screening.evidential_weight == "prospective"


def test_stratum_b_enumerates_investigation_record_domains() -> None:
    assert "ntsb_public_investigation_dockets_all_modes" in STRATUM_B_DOMAINS
    assert len(set(STRATUM_B_DOMAINS)) == len(STRATUM_B_DOMAINS)


# --- Verdict controls --------------------------------------------------------------


def test_kill_public_substrate_is_unreachable_by_this_instrument() -> None:
    with pytest.raises(CensusError, match="bounded frame cannot establish an unbounded negative"):
        reject_unreachable_verdict("KILL_PUBLIC_SUBSTRATE")


def test_every_census_verdict_is_reachable() -> None:
    for verdict in CensusVerdict:
        reject_unreachable_verdict(verdict.value)


def test_qualifying_verdict_requires_a_passing_candidate() -> None:
    failing = (
        GateResult(
            gate=CensusGate.RIGHTS_AND_TERMS,
            status=GateStatus.FAILED,
            supporting_locators=(_locator(source_id="src"),),
            rationale="Blocked.",
        ),
        *[
            GateResult(gate=gate, status=GateStatus.NOT_SCREENED, rationale="Stopped.")
            for gate in GATE_ORDER[1:]
        ],
    )
    screening = CandidateScreening(
        source_id="src",
        domain_id="d",
        stratum=Stratum.PROSPECTIVE,
        object_class=ObjectClass.DATASET_RELEASE,
        gate_results=failing,
    )
    with pytest.raises(ValidationError, match="requires at least one passing candidate"):
        _report((screening,), CensusVerdict.QUALIFYING_CANDIDATE)


def test_null_verdict_is_invalid_when_a_candidate_passed() -> None:
    screening = CandidateScreening(
        source_id="src",
        domain_id="d",
        stratum=Stratum.PROSPECTIVE,
        object_class=ObjectClass.INVESTIGATION_RECORD,
        gate_results=_passing_gates(source_id="src"),
    )
    with pytest.raises(ValidationError, match="invalid when a candidate passed"):
        _report((screening,), CensusVerdict.NULL_WITHIN_FRAME)


def test_empty_frame_returns_a_full_weight_null() -> None:
    report = verify_census_report(_report((), CensusVerdict.NULL_WITHIN_FRAME))
    assert report.verdict is CensusVerdict.NULL_WITHIN_FRAME
    assert report.nominations == ()


# --- Report binding controls -------------------------------------------------------


def test_report_must_bind_the_approved_amendment_document() -> None:
    with pytest.raises(ValidationError, match="approved amendment document"):
        CensusReport(
            iteration_id="iter001_physical_causal_evidence_acquisition",
            amendment_document_artifact_sha256="0" * 64,
            resource_usage=_usage(),
            machine_proposal_artifact_sha256=MACHINE_PROPOSAL_SHA256,
            owner_approval_receipt_hash=OWNER_APPROVAL_RECEIPT_HASH,
            frame_scope="scope",
            frame_declared_incomplete=True,
            screenings=(),
            verdict=CensusVerdict.NULL_WITHIN_FRAME,
            produced_at=NOW,
        )


def test_report_must_bind_the_approved_machine_proposal() -> None:
    with pytest.raises(ValidationError, match="approved machine proposal"):
        CensusReport(
            iteration_id="iter001_physical_causal_evidence_acquisition",
            amendment_document_artifact_sha256=AMENDMENT_DOCUMENT_SHA256,
            machine_proposal_artifact_sha256="0" * 64,
            resource_usage=_usage(),
            owner_approval_receipt_hash=OWNER_APPROVAL_RECEIPT_HASH,
            frame_scope="scope",
            frame_declared_incomplete=True,
            screenings=(),
            verdict=CensusVerdict.NULL_WITHIN_FRAME,
            produced_at=NOW,
        )


def test_report_must_bind_the_owner_approval_receipt() -> None:
    with pytest.raises(ValidationError, match="owner-approval receipt"):
        CensusReport(
            iteration_id="iter001_physical_causal_evidence_acquisition",
            amendment_document_artifact_sha256=AMENDMENT_DOCUMENT_SHA256,
            machine_proposal_artifact_sha256=MACHINE_PROPOSAL_SHA256,
            owner_approval_receipt_hash="0" * 64,
            resource_usage=_usage(),
            frame_scope="scope",
            frame_declared_incomplete=True,
            screenings=(),
            verdict=CensusVerdict.NULL_WITHIN_FRAME,
            produced_at=NOW,
        )


def test_frame_must_be_declared_incomplete() -> None:
    with pytest.raises(ValidationError):
        CensusReport(
            iteration_id="iter001_physical_causal_evidence_acquisition",
            amendment_document_artifact_sha256=AMENDMENT_DOCUMENT_SHA256,
            machine_proposal_artifact_sha256=MACHINE_PROPOSAL_SHA256,
            owner_approval_receipt_hash=OWNER_APPROVAL_RECEIPT_HASH,
            frame_scope="scope",
            frame_declared_incomplete=False,  # type: ignore[arg-type]
            resource_usage=_usage(),
            screenings=(),
            verdict=CensusVerdict.NULL_WITHIN_FRAME,
            produced_at=NOW,
        )


def test_naive_report_time_is_rejected() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        CensusReport(
            iteration_id="iter001_physical_causal_evidence_acquisition",
            amendment_document_artifact_sha256=AMENDMENT_DOCUMENT_SHA256,
            machine_proposal_artifact_sha256=MACHINE_PROPOSAL_SHA256,
            owner_approval_receipt_hash=OWNER_APPROVAL_RECEIPT_HASH,
            frame_scope="scope",
            frame_declared_incomplete=True,
            screenings=(),
            verdict=CensusVerdict.NULL_WITHIN_FRAME,
            resource_usage=_usage(),
            produced_at=datetime(2026, 7, 16, 12, 0, 0),  # noqa: DTZ001
        )


def test_a_source_may_be_screened_at_most_once() -> None:
    screening = CandidateScreening(
        source_id="src",
        domain_id="d",
        stratum=Stratum.PROSPECTIVE,
        object_class=ObjectClass.INVESTIGATION_RECORD,
        gate_results=_passing_gates(source_id="src"),
    )
    with pytest.raises(ValidationError, match="at most once per census"):
        _report((screening, screening), CensusVerdict.QUALIFYING_CANDIDATE)


def test_future_dated_report_is_rejected() -> None:
    report = _report((), CensusVerdict.NULL_WITHIN_FRAME).model_copy(
        update={"produced_at": datetime.now(UTC) + timedelta(days=1)}
    )
    with pytest.raises(CensusError, match="dated in the future"):
        verify_census_report(report)


# --- Resource ceiling controls (Amendment 002 freezes the ceiling) -----------------


def test_a_report_cannot_be_built_without_a_resource_measurement() -> None:
    # missing_measurement_invalidates_audit: an unmeasured audit is invalid, not unconstrained.
    with pytest.raises(ValidationError):
        CensusReport(
            iteration_id="iter001_physical_causal_evidence_acquisition",
            amendment_document_artifact_sha256=AMENDMENT_DOCUMENT_SHA256,
            machine_proposal_artifact_sha256=MACHINE_PROPOSAL_SHA256,
            owner_approval_receipt_hash=OWNER_APPROVAL_RECEIPT_HASH,
            frame_scope="scope",
            frame_declared_incomplete=True,
            screenings=(),
            verdict=CensusVerdict.NULL_WITHIN_FRAME,
            produced_at=NOW,
        )  # type: ignore[call-arg]


@pytest.mark.parametrize(
    ("field", "value", "dimension"),
    [
        ("cpu_seconds", CEILING_CPU_SECONDS + 1, "cpu_seconds"),
        ("wall_seconds", CEILING_WALL_SECONDS + 1, "wall_seconds"),
        ("peak_memory_bytes", CEILING_PEAK_MEMORY_BYTES + 1, "peak_memory_bytes"),
        ("retrieved_bytes", CEILING_RETRIEVED_BYTES + 1, "retrieved_bytes"),
        ("peak_staged_bytes", CEILING_PEAK_STAGED_BYTES + 1, "peak_staged_bytes"),
    ],
)
def test_each_ceiling_dimension_fails_closed(field: str, value: float, dimension: str) -> None:
    usage = _usage(**{field: value})
    assert usage.ceiling_breaches == (dimension,)
    report = _report((), CensusVerdict.NULL_WITHIN_FRAME).model_copy(
        update={"resource_usage": usage}
    )
    with pytest.raises(CensusError, match="exceeded its frozen resource ceiling"):
        verify_census_report(report)


def test_usage_exactly_at_the_ceiling_is_permitted() -> None:
    usage = _usage(
        cpu_seconds=CEILING_CPU_SECONDS,
        wall_seconds=CEILING_WALL_SECONDS,
        peak_memory_bytes=CEILING_PEAK_MEMORY_BYTES,
        retrieved_bytes=CEILING_RETRIEVED_BYTES,
        peak_staged_bytes=CEILING_PEAK_STAGED_BYTES,
    )
    assert usage.ceiling_breaches == ()


def test_multiple_simultaneous_breaches_are_all_reported() -> None:
    usage = _usage(
        cpu_seconds=CEILING_CPU_SECONDS + 1,
        retrieved_bytes=CEILING_RETRIEVED_BYTES + 1,
    )
    assert usage.ceiling_breaches == ("cpu_seconds", "retrieved_bytes")


@pytest.mark.parametrize(
    ("field", "value"),
    [("gpu_seconds", 1), ("cloud_jobs", 1), ("paid_calls", 1), ("cost_usd", "0.01")],
)
def test_zero_authority_dimensions_cannot_record_spend(field: str, value: object) -> None:
    # The amendment grants zero GPU, cloud, paid-provider, and cost authority. An audit must
    # be unable to record spend it was never authorized to make.
    with pytest.raises(ValidationError):
        _usage(**{field: value})


def test_naive_measurement_time_is_rejected() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        _usage(measured_at=datetime(2026, 7, 16, 12, 0, 0))  # noqa: DTZ001


def test_measurement_primitive_measures_real_cpu_and_wall_time() -> None:
    with measure_census_resources() as observed:
        total = sum(i * i for i in range(200_000))
    assert total > 0
    assert observed["wall_seconds"] > 0
    assert observed["cpu_seconds"] >= 0
    assert observed["peak_memory_bytes"] > 0
    # The measured values must be usable as a real audit measurement, not a placeholder.
    usage = CensusResourceUsage(
        cpu_seconds=observed["cpu_seconds"],
        wall_seconds=observed["wall_seconds"],
        peak_memory_bytes=int(observed["peak_memory_bytes"]),
        retrieved_bytes=0,
        peak_staged_bytes=0,
        measurement_method="resource.getrusage+time.perf_counter",
        measured_at=datetime.now(UTC),
    )
    assert usage.ceiling_breaches == ()


def test_census_subject_hash_is_domain_separated_and_stable() -> None:
    first = census_subject_hash("candidate", {"source_id": "a"})
    second = census_subject_hash("candidate", {"source_id": "a"})
    other = census_subject_hash("report", {"source_id": "a"})
    assert first == second
    assert first != other
