"""Diagnosis-method port, reference likelihood baseline, and the paired campaign.

Authorized by owner-approval receipt `iter001-method-campaign-owner-approval-005`
(`approve_method_campaign_implementation_only`) over Amendment 005 at proposal commit
`db509e67d4edac8b71f332c9fecb5a995d626585`.

This module authorizes implementation only. A campaign run requires the causal-laboratory
compute lease Amendment 004 defined, signed by the owner governance key. A campaign result
establishes how the reference baseline behaves inside the reference simulator against injected
truth, and nothing about the physical world: a simulator branch never counts as a physical
incident.

The unit under test is the mission's central hypothesis, expressed in-simulator. A method reads
the telemetry of the branches a condition permits, blind to the injected mechanism, and names one
mechanism or abstains to the reserved unknown. Under `passive` it sees only the no-op branch;
under `active` it additionally sees the targeted-test branch. The paired design injects one
mechanism, diagnoses it under both conditions, and adjudicates each against the revealed truth,
so a passive/active difference is attributable to the discriminating test, not to episode luck.
"""

from __future__ import annotations

from datetime import datetime
from decimal import ROUND_HALF_EVEN, Decimal
from typing import Final, Literal, Protocol, Self, runtime_checkable

from pydantic import Field, model_validator

from fieldtrue.canonical import sha256_value
from fieldtrue.causal_laboratory import (
    AMENDMENT_DOCUMENT_SHA256 as _LAB_AMENDMENT_DOC,
)
from fieldtrue.causal_laboratory import (
    MACHINE_PROPOSAL_SHA256 as _LAB_MACHINE_PROPOSAL,
)
from fieldtrue.causal_laboratory import (
    OWNER_APPROVAL_RECEIPT_HASH as _LAB_RECEIPT,
)
from fieldtrue.causal_laboratory import (
    UNKNOWN_MECHANISM_KEY,
    BranchKind,
    BranchSet,
    CausalLabComputeLease,
    EpisodeReport,
    LabHypothesisSet,
    MechanismOntology,
    ReferenceFaultConfig,
    SealedMechanism,
    adjudicate_episode,
    reference_branch,
    reference_forward_telemetry,
    reference_snapshot,
    verify_lab_compute_lease,
)
from fieldtrue.domain import (
    Ed25519PublicKey,
    FrozenModel,
    GitObjectId,
    Identifier,
    Sha256,
)
from fieldtrue.shortcut_contracts import OWNER_PUBLIC_KEY

AMENDMENT_ID: Final = "iter001_005"
APPROVED_PROPOSAL_COMMIT: Final = "db509e67d4edac8b71f332c9fecb5a995d626585"
AMENDMENT_DOCUMENT_SHA256: Final = (
    "0ff5916abc82a7b51c7f67adb25c5e18abbe1a3d95dfcb46f4e35783d126cf2b"
)
MACHINE_PROPOSAL_SHA256: Final = "c0fe0c6447de04ed7e30f81fc6db12d96fc5cf7883729aeabb53d1577ed5a87d"
OWNER_APPROVAL_RECEIPT_HASH: Final = (
    "e660be502da65893c03b0638376ea7a5d27b902f462eb89ad108633bb872fad4"
)

REFERENCE_BASELINE_METHOD_ID: Final = "reference_likelihood_diagnoser"


class MethodCampaignError(ValueError):
    """A method port, campaign plan, episode, or result is invalid."""


# --- Frozen reference operating point ------------------------------------------------
#
# The reference baseline's forward models are frozen against this single operating point. The
# campaign builds every branch at exactly this point, so the baseline's noise-free predictions and
# the observed telemetry share a nominal model and differ only by the sealed disturbance and the
# injected mechanism. Freezing the point in the baseline honors the amendment's observation
# contract: a method sees only branch telemetry and the ontology, never these numeric parameters.

REFERENCE_BASELINE_CONFIG: Final = ReferenceFaultConfig(gain=90, drive=50, bias=10, steps=8)
REFERENCE_BASELINE_INITIAL_STATE: Final = 100
_STEPS: Final = REFERENCE_BASELINE_CONFIG.steps
NO_OP_ACTION: Final[tuple[int, ...]] = (0,) * _STEPS
TARGETED_TEST_ACTION: Final[tuple[int, ...]] = (100,) * _STEPS
WRONG_BUT_SAFE_ACTION: Final[tuple[int, ...]] = (10,) * _STEPS
RECOVERY_ACTION: Final[tuple[int, ...]] = (60,) * _STEPS

_ACTION_BY_KIND: Final[dict[BranchKind, tuple[int, ...]]] = {
    BranchKind.NO_OP: NO_OP_ACTION,
    BranchKind.TARGETED_TEST: TARGETED_TEST_ACTION,
    BranchKind.WRONG_BUT_SAFE: WRONG_BUT_SAFE_ACTION,
    BranchKind.RECOVERY: RECOVERY_ACTION,
    BranchKind.BLOCKED_UNSAFE: NO_OP_ACTION,
}

# The two evidence conditions, each naming the branch kinds a method is permitted to observe.
PASSIVE_PERMITTED: Final[tuple[BranchKind, ...]] = (BranchKind.NO_OP,)
ACTIVE_PERMITTED: Final[tuple[BranchKind, ...]] = (BranchKind.NO_OP, BranchKind.TARGETED_TEST)

# Frozen decision constants of the reference likelihood baseline.
LIKELIHOOD_SCALE: Final = 4  # residual units per e-fold of likelihood
CONFIDENCE_FLOOR: Final = Decimal("0.600000")  # commit only above this posterior
TIE_MARGIN: Final = 2  # two smallest residuals within this many units -> abstain

_METRIC = Decimal("0.000001")


def _fmt(value: Decimal) -> str:
    return str(value.quantize(_METRIC, rounding=ROUND_HALF_EVEN))


# --- The diagnosis-method port -------------------------------------------------------


class MethodBranchObservation(FrozenModel):
    """The model-visible content of one permitted branch: what was commanded and what was seen.

    It carries no settled-state hash, no sealed mechanism, and no salt. The observation type
    structurally cannot transport the injected truth to the method.
    """

    schema_version: Literal["inbar.iter001.method-branch-observation.v1"] = (
        "inbar.iter001.method-branch-observation.v1"
    )
    kind: BranchKind
    action: tuple[int, ...]
    telemetry: tuple[int, ...]


class MethodObservation(FrozenModel):
    """Everything a method is permitted to see for one episode-condition.

    Only the ontology (keys and definitions), the candidate known keys, and the telemetry of the
    permitted branches. A blocked-unsafe branch is never permitted; it carries no telemetry.
    """

    schema_version: Literal["inbar.iter001.method-observation.v1"] = (
        "inbar.iter001.method-observation.v1"
    )
    ontology_hash: Sha256
    candidate_known_keys: tuple[Sha256, ...] = Field(min_length=2)
    branches: tuple[MethodBranchObservation, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def keys_unique_and_branches_permitted(self) -> Self:
        if len(set(self.candidate_known_keys)) != len(self.candidate_known_keys):
            raise ValueError("candidate known keys must be unique")
        kinds = [b.kind for b in self.branches]
        if len(set(kinds)) != len(kinds):
            raise ValueError("a method observation must not repeat a branch kind")
        if BranchKind.BLOCKED_UNSAFE in set(kinds):
            raise ValueError("a blocked-unsafe branch is never a permitted observation")
        return self


class MethodDiagnosis(FrozenModel):
    """A method's committed output: the hypotheses it carried and the single key it selected.

    `diagnosis_key` is one of the candidate known keys or the reserved unknown. Abstention is
    naming the unknown. `confidence` is the method's stated posterior for the selected key, a
    deterministic six-decimal string so a campaign result is reproducible byte for byte.
    """

    schema_version: Literal["inbar.iter001.method-diagnosis.v1"] = (
        "inbar.iter001.method-diagnosis.v1"
    )
    method_id: Identifier
    known_keys: tuple[Sha256, ...] = Field(min_length=2)
    diagnosis_key: str = Field(min_length=1)
    confidence: str = Field(pattern=r"^(0\.[0-9]{6}|1\.000000)$")
    abstained: bool
    committed_at: datetime

    @model_validator(mode="after")
    def diagnosis_is_a_carried_hypothesis(self) -> Self:
        if len(set(self.known_keys)) != len(self.known_keys):
            raise ValueError("method known keys must be unique")
        candidates = set(self.known_keys) | {UNKNOWN_MECHANISM_KEY}
        if self.diagnosis_key not in candidates:
            raise ValueError("diagnosis names a key the method did not carry")
        # Abstention emits the reserved unknown. Naming the unknown is not always abstention: a
        # method may confidently diagnose that the truth is genuinely unmodeled. So abstention
        # implies the unknown key, but the unknown key does not imply abstention.
        if self.abstained and self.diagnosis_key != UNKNOWN_MECHANISM_KEY:
            raise ValueError("an abstaining method must emit the reserved unknown")
        if self.committed_at.tzinfo is None or self.committed_at.utcoffset() is None:
            raise ValueError("method commitment time must be timezone-aware")
        return self


@runtime_checkable
class DiagnosisMethod(Protocol):
    """A provider-neutral diagnosis port. It reads an observation and returns a diagnosis.

    It is called before adjudication and receives no route to the sealed truth. A future adapter
    (a learned method, a different simulator) implements the same port.
    """

    method_id: str

    def diagnose(self, observation: MethodObservation) -> MethodDiagnosis: ...


# --- The reference likelihood baseline -----------------------------------------------


def _residual(observed: tuple[int, ...], predicted: tuple[int, ...]) -> int:
    return sum(abs(o - p) for o, p in zip(observed, predicted, strict=True))


class ReferenceLikelihoodDiagnoser:
    """Deterministic max-likelihood baseline over the reference simulator's frozen forward models.

    For each candidate mechanism it predicts the noise-free telemetry of every permitted branch at
    the frozen operating point, sums the absolute residual against the observation, and scores the
    mechanism by a residual-driven likelihood. It diagnoses the single most likely mechanism and
    abstains to the reserved unknown when the posterior is below the confidence floor or the two
    smallest residuals tie within the margin. It is representation-free and reads only the
    permitted telemetry; it is a baseline, not a learned system.
    """

    method_id: str = REFERENCE_BASELINE_METHOD_ID

    def __init__(self, ontology: MechanismOntology) -> None:
        self._ontology = ontology
        self._known_keys = tuple(sorted(ontology.known_keys))

    def diagnose(self, observation: MethodObservation) -> MethodDiagnosis:
        if observation.ontology_hash != self._ontology.ontology_hash:
            raise MethodCampaignError("observation ontology differs from the method ontology")
        if set(observation.candidate_known_keys) != set(self._known_keys):
            raise MethodCampaignError("observation candidate keys differ from the ontology")

        # Candidate hypotheses: every known mechanism plus the reserved unknown (nominal model).
        candidates = [*self._known_keys, UNKNOWN_MECHANISM_KEY]
        residuals: dict[str, int] = {}
        for key in candidates:
            total = 0
            for branch in observation.branches:
                predicted = reference_forward_telemetry(
                    config=REFERENCE_BASELINE_CONFIG,
                    initial_state=REFERENCE_BASELINE_INITIAL_STATE,
                    mechanism_key=key,
                    action=branch.action,
                )
                total += _residual(branch.telemetry, predicted)
            residuals[key] = total

        ordered = sorted(candidates, key=lambda k: (residuals[k], k))
        best, runner_up = ordered[0], ordered[1]
        tie = residuals[runner_up] - residuals[best] <= TIE_MARGIN

        # Posterior over an exponential likelihood in the residual, computed in Decimal so the
        # stored confidence and the commit/abstain decision are identical on every platform.
        weights = {
            k: (-Decimal(residuals[k]) / Decimal(LIKELIHOOD_SCALE)).exp() for k in candidates
        }
        total_weight = sum(weights.values(), start=Decimal(0))
        posterior_best = (weights[best] / total_weight).quantize(_METRIC, rounding=ROUND_HALF_EVEN)

        if tie or posterior_best < CONFIDENCE_FLOOR:
            diagnosis_key = UNKNOWN_MECHANISM_KEY
            abstained = True
            confidence = (weights[UNKNOWN_MECHANISM_KEY] / total_weight).quantize(
                _METRIC, rounding=ROUND_HALF_EVEN
            )
        else:
            diagnosis_key = best
            abstained = False
            confidence = posterior_best

        return MethodDiagnosis(
            method_id=self.method_id,
            known_keys=self._known_keys,
            diagnosis_key=diagnosis_key,
            confidence=_fmt(confidence),
            abstained=abstained,
            committed_at=_frozen_commit_time(observation),
        )


def _frozen_commit_time(observation: MethodObservation) -> datetime:
    """A deterministic timezone-aware commitment stamp derived from the observation.

    The baseline is a pure function of its observation; a wall clock would make campaign results
    irreproducible. The stamp is fixed and identical across a run, and always precedes the episode
    production time the runner assigns.
    """
    del observation
    return _BASELINE_COMMIT_TIME


_BASELINE_COMMIT_TIME: Final = datetime.fromisoformat("2026-07-17T00:00:00+00:00")


# --- Campaign plan (frozen before any run) -------------------------------------------


class PlannedEpisode(FrozenModel):
    """One episode's frozen injection: which mechanism (a known name or unknown) and its salt."""

    schema_version: Literal["inbar.iter001.campaign-planned-episode.v1"] = (
        "inbar.iter001.campaign-planned-episode.v1"
    )
    episode_id: Identifier
    injected_name: str = Field(min_length=1)
    snapshot_seed: int = Field(ge=0)
    salt_hex: str = Field(pattern=r"^[0-9a-f]{64}$")


class CampaignPlan(FrozenModel):
    """The complete, pre-committed episode schedule. Its hash is bound into the result.

    The injection distribution, seed schedule, and episode count are fixed here before the run and
    cannot be chosen after inspecting outcomes.
    """

    schema_version: Literal["inbar.iter001.campaign-plan.v1"] = "inbar.iter001.campaign-plan.v1"
    plan_id: Identifier
    ontology_hash: Sha256
    episodes: tuple[PlannedEpisode, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def episode_ids_are_unique(self) -> Self:
        ids = [e.episode_id for e in self.episodes]
        if len(set(ids)) != len(ids):
            raise ValueError("campaign episode ids must be unique")
        return self

    @property
    def plan_hash(self) -> str:
        return sha256_value(
            {
                "schema_version": self.schema_version,
                "episodes": [e.model_dump(mode="json") for e in self.episodes],
                "ontology_hash": self.ontology_hash,
                "plan_id": self.plan_id,
            }
        )


# --- Episode-condition outcome (the atomic record the result recomputes from) --------

Condition = Literal["passive", "active"]


class ConditionOutcome(FrozenModel):
    """The adjudicated diagnosis of one episode under one evidence condition."""

    schema_version: Literal["inbar.iter001.campaign-condition-outcome.v1"] = (
        "inbar.iter001.campaign-condition-outcome.v1"
    )
    episode_id: Identifier
    condition: Condition
    injected_key: str
    injected_was_unknown: bool
    identifiable: bool
    diagnosis_key: str
    diagnosis_correct: bool
    abstained: bool
    confidence: str = Field(pattern=r"^(0\.[0-9]{6}|1\.000000)$")


class EpisodeOutcome(FrozenModel):
    """Both conditions for one paired episode, plus the episode report hashes for audit."""

    schema_version: Literal["inbar.iter001.campaign-episode-outcome.v1"] = (
        "inbar.iter001.campaign-episode-outcome.v1"
    )
    episode_id: Identifier
    injected_key: str
    passive: ConditionOutcome
    active: ConditionOutcome
    passive_episode_hash: Sha256
    active_episode_hash: Sha256

    @model_validator(mode="after")
    def conditions_are_the_pair(self) -> Self:
        if self.passive.condition != "passive" or self.active.condition != "active":
            raise ValueError("an episode outcome pairs exactly one passive and one active result")
        if self.passive.episode_id != self.episode_id or self.active.episode_id != self.episode_id:
            raise ValueError("paired outcomes must share the episode id")
        if self.passive.injected_key != self.injected_key or (
            self.active.injected_key != self.injected_key
        ):
            raise ValueError("paired outcomes must share the injected key")
        return self


# --- Comparative result --------------------------------------------------------------


class ConditionSummary(FrozenModel):
    schema_version: Literal["inbar.iter001.campaign-condition-summary.v1"] = (
        "inbar.iter001.campaign-condition-summary.v1"
    )
    condition: Condition
    episodes: int = Field(ge=1)
    diagnosis_accuracy: str = Field(pattern=r"^(0\.[0-9]{6}|1\.000000)$")
    abstention_rate: str = Field(pattern=r"^(0\.[0-9]{6}|1\.000000)$")
    abstention_correct_rate: str = Field(pattern=r"^(0\.[0-9]{6}|1\.000000)$")
    committed_accuracy: str = Field(pattern=r"^(0\.[0-9]{6}|1\.000000)$")
    committed_mean_confidence: str = Field(pattern=r"^(0\.[0-9]{6}|1\.000000)$")
    unknown_injection_accuracy: str = Field(pattern=r"^(0\.[0-9]{6}|1\.000000)$")


class CampaignResult(FrozenModel):
    """The comparative result, binding every authority and recomputed from the episode records."""

    schema_version: Literal["inbar.iter001.campaign-result.v1"] = "inbar.iter001.campaign-result.v1"
    result_id: Identifier
    amendment_document_artifact_sha256: Sha256
    machine_proposal_artifact_sha256: Sha256
    owner_approval_receipt_hash: Sha256
    proposal_git_commit: GitObjectId
    method_id: Identifier
    ontology_hash: Sha256
    simulator_id: Identifier
    plan_hash: Sha256
    compute_lease_hash: Sha256
    episodes: int = Field(ge=1)
    passive: ConditionSummary
    active: ConditionSummary
    paired_active_minus_passive_accuracy: str = Field(pattern=r"^-?(0\.[0-9]{6}|1\.000000)$")
    paired_interval_low: str = Field(pattern=r"^-?(0\.[0-9]{6}|1\.000000)$")
    paired_interval_high: str = Field(pattern=r"^-?(0\.[0-9]{6}|1\.000000)$")
    active_strictly_helps: bool

    @model_validator(mode="after")
    def binds_the_approved_artifacts(self) -> Self:
        if self.amendment_document_artifact_sha256 != AMENDMENT_DOCUMENT_SHA256:
            raise ValueError("result does not bind the approved amendment document")
        if self.machine_proposal_artifact_sha256 != MACHINE_PROPOSAL_SHA256:
            raise ValueError("result does not bind the approved machine proposal")
        if self.owner_approval_receipt_hash != OWNER_APPROVAL_RECEIPT_HASH:
            raise ValueError("result does not bind the owner-approval receipt")
        if self.proposal_git_commit != APPROVED_PROPOSAL_COMMIT:
            raise ValueError("result does not bind the approved proposal commit")
        return self


# --- Identifiability (ground-truth property, used only to score abstention) ----------


def _mechanism_identifiable(
    injected_key: str, permitted: tuple[BranchKind, ...], ontology: MechanismOntology
) -> bool:
    """Is the injected mechanism distinguishable from every other candidate on the permitted set?

    Computed from the noise-free forward models at the frozen operating point: the injected
    mechanism is identifiable when its predicted telemetry differs from that of every other
    candidate on at least one permitted branch. This is a ground-truth property (it uses the
    injected key), so it is available only to the adjudicating custodian, never to the method. It
    scores whether an abstention was the honest response to genuinely ambiguous evidence.
    """
    candidates = [*sorted(ontology.known_keys), UNKNOWN_MECHANISM_KEY]
    others = [k for k in candidates if k != injected_key]
    injected_pred = {
        kind: reference_forward_telemetry(
            config=REFERENCE_BASELINE_CONFIG,
            initial_state=REFERENCE_BASELINE_INITIAL_STATE,
            mechanism_key=injected_key,
            action=_ACTION_BY_KIND[kind],
        )
        for kind in permitted
    }
    for other in others:
        distinguishable = False
        for kind in permitted:
            other_pred = reference_forward_telemetry(
                config=REFERENCE_BASELINE_CONFIG,
                initial_state=REFERENCE_BASELINE_INITIAL_STATE,
                mechanism_key=other,
                action=_ACTION_BY_KIND[kind],
            )
            if other_pred != injected_pred[kind]:
                distinguishable = True
                break
        if not distinguishable:
            return False
    return True


# --- Running one condition -----------------------------------------------------------


def _observation_for(
    branch_set: BranchSet,
    telemetry_by_kind: dict[BranchKind, tuple[int, ...]],
    permitted: tuple[BranchKind, ...],
    ontology: MechanismOntology,
) -> MethodObservation:
    branches = tuple(
        MethodBranchObservation(
            kind=kind,
            action=_ACTION_BY_KIND[kind],
            telemetry=telemetry_by_kind[kind],
        )
        for kind in permitted
    )
    return MethodObservation(
        ontology_hash=ontology.ontology_hash,
        candidate_known_keys=tuple(sorted(ontology.known_keys)),
        branches=branches,
    )


def _run_condition(
    *,
    condition: Condition,
    permitted: tuple[BranchKind, ...],
    method: DiagnosisMethod,
    ontology: MechanismOntology,
    sealed: SealedMechanism,
    branch_set: BranchSet,
    telemetry_by_kind: dict[BranchKind, tuple[int, ...]],
    episode_id: str,
    injected_key: str,
    salt_hex: str,
    produced_at: datetime,
) -> tuple[ConditionOutcome, str]:
    observation = _observation_for(branch_set, telemetry_by_kind, permitted, ontology)
    diagnosis = method.diagnose(observation)
    permitted_candidates = set(observation.candidate_known_keys) | {UNKNOWN_MECHANISM_KEY}
    if diagnosis.diagnosis_key not in permitted_candidates:
        raise MethodCampaignError("method diagnosed a key outside the permitted candidate set")

    hypothesis_set = LabHypothesisSet(
        ontology_hash=ontology.ontology_hash,
        known_keys=diagnosis.known_keys,
        committed_at=diagnosis.committed_at,
    )
    episode = EpisodeReport(
        episode_id=f"{episode_id}-{condition}",
        amendment_document_artifact_sha256=_LAB_AMENDMENT_DOC,
        machine_proposal_artifact_sha256=_LAB_MACHINE_PROPOSAL,
        owner_approval_receipt_hash=_LAB_RECEIPT,
        ontology_hash=ontology.ontology_hash,
        sealed_mechanism=sealed,
        branch_set=branch_set,
        hypothesis_set=hypothesis_set,
        diagnosis_key=diagnosis.diagnosis_key,
        produced_at=produced_at,
    )
    adjudication = adjudicate_episode(
        episode,
        injected_key=injected_key,
        salt_hex=salt_hex,
        known_ontology_keys=ontology.known_keys,
        at=produced_at,
    )
    identifiable = _mechanism_identifiable(injected_key, permitted, ontology)
    outcome = ConditionOutcome(
        episode_id=episode_id,
        condition=condition,
        injected_key=injected_key,
        injected_was_unknown=adjudication.injected_was_unknown,
        identifiable=identifiable,
        diagnosis_key=diagnosis.diagnosis_key,
        diagnosis_correct=adjudication.diagnosis_correct,
        abstained=diagnosis.abstained,
        confidence=diagnosis.confidence,
    )
    return outcome, sha256_value(episode.model_dump(mode="json"))


def run_campaign(
    *,
    plan: CampaignPlan,
    method: DiagnosisMethod,
    ontology: MechanismOntology,
    lease: CausalLabComputeLease,
    result_id: Identifier,
    produced_at: datetime,
    expected_public_key: Ed25519PublicKey = OWNER_PUBLIC_KEY,
    at: datetime | None = None,
) -> tuple[CampaignResult, tuple[EpisodeOutcome, ...]]:
    """Run the paired passive/active campaign under a verified compute lease.

    The lease is verified first and fails closed; no lease, no run. Each episode injects one
    mechanism, builds the five-branch set at the frozen operating point, diagnoses it under both
    conditions blind to the injection, and adjudicates each against the revealed truth. The result
    is recomputed from the produced outcomes so no aggregate is asserted rather than derived.
    """
    if plan.ontology_hash != ontology.ontology_hash:
        raise MethodCampaignError("campaign plan does not bind the method ontology")
    verify_lab_compute_lease(
        lease, ontology_hash=ontology.ontology_hash, expected_public_key=expected_public_key, at=at
    )
    if produced_at.tzinfo is None or produced_at.utcoffset() is None:
        raise MethodCampaignError("campaign production time must be timezone-aware")
    if produced_at < _BASELINE_COMMIT_TIME:
        raise MethodCampaignError("campaign production time precedes the frozen method commitment")

    name_to_key = {c.name: c.key for c in ontology.classes}
    outcomes: list[EpisodeOutcome] = []
    for planned in plan.episodes:
        if planned.injected_name == UNKNOWN_MECHANISM_KEY:
            injected_key = UNKNOWN_MECHANISM_KEY
        elif planned.injected_name in name_to_key:
            injected_key = name_to_key[planned.injected_name]
        else:
            raise MethodCampaignError("planned injection names an unknown mechanism")

        snapshot = reference_snapshot(
            config=REFERENCE_BASELINE_CONFIG,
            initial_state=REFERENCE_BASELINE_INITIAL_STATE,
            seed=planned.snapshot_seed,
        )
        sealed = SealedMechanism.commit(
            ontology_hash=ontology.ontology_hash,
            injected_key=injected_key,
            salt_hex=planned.salt_hex,
        )
        branches = []
        telemetry_by_kind: dict[BranchKind, tuple[int, ...]] = {}
        for kind in BranchKind:
            branch, telemetry = reference_branch(
                kind=kind,
                snapshot=snapshot,
                config=REFERENCE_BASELINE_CONFIG,
                initial_state=REFERENCE_BASELINE_INITIAL_STATE,
                injected_key=injected_key,
                action=_ACTION_BY_KIND[kind],
            )
            branches.append(branch)
            telemetry_by_kind[kind] = telemetry
        branch_set = BranchSet(snapshot=snapshot, branches=tuple(branches))

        passive_outcome, passive_hash = _run_condition(
            condition="passive",
            permitted=PASSIVE_PERMITTED,
            method=method,
            ontology=ontology,
            sealed=sealed,
            branch_set=branch_set,
            telemetry_by_kind=telemetry_by_kind,
            episode_id=planned.episode_id,
            injected_key=injected_key,
            salt_hex=planned.salt_hex,
            produced_at=produced_at,
        )
        active_outcome, active_hash = _run_condition(
            condition="active",
            permitted=ACTIVE_PERMITTED,
            method=method,
            ontology=ontology,
            sealed=sealed,
            branch_set=branch_set,
            telemetry_by_kind=telemetry_by_kind,
            episode_id=planned.episode_id,
            injected_key=injected_key,
            salt_hex=planned.salt_hex,
            produced_at=produced_at,
        )
        outcomes.append(
            EpisodeOutcome(
                episode_id=planned.episode_id,
                injected_key=injected_key,
                passive=passive_outcome,
                active=active_outcome,
                passive_episode_hash=passive_hash,
                active_episode_hash=active_hash,
            )
        )

    result = recompute_campaign_result(
        result_id=result_id,
        outcomes=tuple(outcomes),
        method_id=method.method_id,
        ontology=ontology,
        plan=plan,
        lease=lease,
        produced_at=produced_at,
    )
    return result, tuple(outcomes)


# --- Deterministic aggregation (the harness recomputes every reported quantity) ------


def _rate(numerator: int, denominator: int) -> Decimal:
    if denominator == 0:
        return Decimal(0)
    return Decimal(numerator) / Decimal(denominator)


def _summarize(condition: Condition, rows: list[ConditionOutcome]) -> ConditionSummary:
    n = len(rows)
    correct = sum(1 for r in rows if r.diagnosis_correct)
    abstained = [r for r in rows if r.abstained]
    abstain_correct = sum(1 for r in abstained if not r.identifiable)
    committed = [r for r in rows if not r.abstained]
    committed_correct = sum(1 for r in committed if r.diagnosis_correct)
    committed_conf = sum((Decimal(r.confidence) for r in committed), start=Decimal(0))
    unknown_rows = [r for r in rows if r.injected_was_unknown]
    unknown_correct = sum(1 for r in unknown_rows if r.diagnosis_correct)
    return ConditionSummary(
        condition=condition,
        episodes=n,
        diagnosis_accuracy=_fmt(_rate(correct, n)),
        abstention_rate=_fmt(_rate(len(abstained), n)),
        abstention_correct_rate=_fmt(_rate(abstain_correct, len(abstained))),
        committed_accuracy=_fmt(_rate(committed_correct, len(committed))),
        committed_mean_confidence=_fmt(
            committed_conf / Decimal(len(committed)) if committed else Decimal(0)
        ),
        unknown_injection_accuracy=_fmt(_rate(unknown_correct, len(unknown_rows))),
    )


def recompute_campaign_result(
    *,
    result_id: Identifier,
    outcomes: tuple[EpisodeOutcome, ...],
    method_id: str,
    ontology: MechanismOntology,
    plan: CampaignPlan,
    lease: CausalLabComputeLease,
    produced_at: datetime,
) -> CampaignResult:
    """Recompute the comparative result from the atomic outcome records alone.

    Every quantity in the result is derived here from the outcomes; nothing is carried over from
    the run. A control recomputes independently and asserts equality, which is what makes the
    result auditable rather than asserted.
    """
    if not outcomes:
        raise MethodCampaignError("a campaign result needs at least one episode outcome")
    del produced_at  # bound below through the plan and lease, not the wall clock

    passive_rows = [o.passive for o in outcomes]
    active_rows = [o.active for o in outcomes]
    passive = _summarize("passive", passive_rows)
    active = _summarize("active", active_rows)

    # Paired difference: per episode, active_correct - passive_correct in {-1, 0, 1}. Its mean is
    # the paired effect; the interval is a normal-approximation on the episode-clustered paired
    # differences (each episode is one cluster contributing one difference).
    diffs = [int(o.active.diagnosis_correct) - int(o.passive.diagnosis_correct) for o in outcomes]
    n = len(diffs)
    mean = Decimal(sum(diffs)) / Decimal(n)
    if n > 1:
        var_num = sum((Decimal(d) - mean) ** 2 for d in diffs)
        variance = var_num / Decimal(n - 1)
        std_error = (variance.sqrt()) / Decimal(n).sqrt()
    else:
        std_error = Decimal(0)
    half = Decimal("1.959964") * std_error
    low = _clamped(mean - half)
    high = _clamped(mean + half)

    return CampaignResult(
        result_id=result_id,
        amendment_document_artifact_sha256=AMENDMENT_DOCUMENT_SHA256,
        machine_proposal_artifact_sha256=MACHINE_PROPOSAL_SHA256,
        owner_approval_receipt_hash=OWNER_APPROVAL_RECEIPT_HASH,
        proposal_git_commit=APPROVED_PROPOSAL_COMMIT,
        method_id=method_id,
        ontology_hash=ontology.ontology_hash,
        simulator_id="inbar-reference-simulator-v1",
        plan_hash=plan.plan_hash,
        compute_lease_hash=lease.lease_hash,
        episodes=n,
        passive=passive,
        active=active,
        paired_active_minus_passive_accuracy=_fmt(mean),
        paired_interval_low=_fmt(low),
        paired_interval_high=_fmt(high),
        active_strictly_helps=(low > Decimal(0)),
    )


def _clamped(value: Decimal) -> Decimal:
    """Clamp a metric into [-1, 1] before formatting so a wide interval stays in range."""
    if value > Decimal(1):
        return Decimal(1)
    if value < Decimal(-1):
        return Decimal(-1)
    return value
