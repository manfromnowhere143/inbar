"""Adversarial controls for the causal-laboratory harness.

The plane's value is that injected ground truth lets the full method be tested without a second
unexposed reviewer. A harness that let a proposer see the sealed mechanism, a branch set span
two snapshots, a blocked_unsafe branch execute, a diagnosis name a key outside the committed
hypotheses, a reveal that does not open the commitment, or a lease widen the frozen ceiling
would each destroy that value.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from nacl.signing import SigningKey
from pydantic import ValidationError

from fieldtrue.canonical import sha256_value
from fieldtrue.causal_laboratory import (
    AMENDMENT_DOCUMENT_SHA256,
    APPROVED_PROPOSAL_COMMIT,
    MACHINE_PROPOSAL_SHA256,
    OWNER_APPROVAL_RECEIPT_HASH,
    REFERENCE_ONTOLOGY,
    UNKNOWN_MECHANISM_KEY,
    Branch,
    BranchKind,
    BranchSet,
    CausalLabComputeLease,
    CausalLaboratoryError,
    EpisodeReport,
    LabHypothesisSet,
    MechanismClass,
    MechanismOntology,
    ReferenceFaultConfig,
    SealedMechanism,
    _lab_lease_body,
    adjudicate_episode,
    issue_lab_compute_lease,
    reference_action_hash,
    reference_branch,
    reference_snapshot,
    verify_lab_compute_lease,
)

KEY = SigningKey(hashlib.sha256(b"inbar-test-causal-laboratory-signer").digest())
KEY_PUB = KEY.verify_key.encode().hex()
ONTO = REFERENCE_ONTOLOGY
OH = ONTO.ontology_hash
BY_NAME = {c.name: c.key for c in ONTO.classes}
NOW = datetime(2026, 7, 17, 12, 0, 0, tzinfo=UTC)
CFG = ReferenceFaultConfig(gain=90, drive=100, bias=0, steps=6)
SALT = "a" * 64


def _snapshot(seed: int = 7) -> object:
    return reference_snapshot(config=CFG, initial_state=100, seed=seed)


def _branch_set(injected_key: str, snapshot=None) -> BranchSet:
    snap = snapshot or _snapshot()
    actions = {
        BranchKind.NO_OP: (0, 0, 0, 0, 0, 0),
        BranchKind.TARGETED_TEST: (500,) * 6,
        BranchKind.WRONG_BUT_SAFE: (1,) * 6,
        BranchKind.RECOVERY: (200, 0) * 3,
        BranchKind.BLOCKED_UNSAFE: (99999,) * 6,
    }
    branches = [
        reference_branch(
            kind=kind,
            snapshot=snap,
            config=CFG,
            initial_state=100,
            injected_key=injected_key,
            action=act,
        )[0]
        for kind, act in actions.items()
    ]
    return BranchSet(snapshot=snap, branches=tuple(branches))


def _hypotheses(known: tuple[str, str] | None = None) -> LabHypothesisSet:
    known = known or (BY_NAME["actuator_loss"], BY_NAME["gain_drift"])
    return LabHypothesisSet(ontology_hash=OH, known_keys=known, committed_at=NOW)


def _episode(injected_key: str, diagnosis_key: str, **overrides: object) -> EpisodeReport:
    values: dict[str, object] = {
        "episode_id": "episode-1",
        "amendment_document_artifact_sha256": AMENDMENT_DOCUMENT_SHA256,
        "machine_proposal_artifact_sha256": MACHINE_PROPOSAL_SHA256,
        "owner_approval_receipt_hash": OWNER_APPROVAL_RECEIPT_HASH,
        "ontology_hash": OH,
        "sealed_mechanism": SealedMechanism.commit(
            ontology_hash=OH, injected_key=injected_key, salt_hex=SALT
        ),
        "branch_set": _branch_set(injected_key),
        "hypothesis_set": _hypotheses(),
        "diagnosis_key": diagnosis_key,
        "produced_at": NOW + timedelta(minutes=30),
    }
    values.update(overrides)
    return EpisodeReport(**values)  # type: ignore[arg-type]


# --- Ontology controls -------------------------------------------------------------


def test_reference_ontology_has_unique_keys_and_reserves_unknown() -> None:
    assert len(ONTO.known_keys) == 3
    assert UNKNOWN_MECHANISM_KEY not in {c.name for c in ONTO.classes}


def test_ontology_rejects_duplicate_classes() -> None:
    c = MechanismClass(name="dup", causal_locus="a", failure_mode="b", definition="c")
    with pytest.raises(ValidationError, match="unique keys"):
        MechanismOntology(classes=(c, c))


def test_a_class_cannot_use_the_reserved_unknown_name() -> None:
    with pytest.raises(ValidationError, match="reserved unknown"):
        MechanismOntology(
            classes=(
                MechanismClass(name="unknown", causal_locus="a", failure_mode="b", definition="c"),
                MechanismClass(name="real", causal_locus="d", failure_mode="e", definition="f"),
            )
        )


def test_mechanism_key_derives_from_definition_not_name() -> None:
    a = MechanismClass(name="x", causal_locus="loc", failure_mode="fm", definition="def")
    b = MechanismClass(name="x", causal_locus="loc", failure_mode="fm", definition="OTHER")
    assert a.key != b.key


# --- Sealed mechanism controls -----------------------------------------------------


def test_sealed_commitment_opens_only_to_the_true_key_and_salt() -> None:
    sealed = SealedMechanism.commit(
        ontology_hash=OH, injected_key=BY_NAME["sensor_bias"], salt_hex=SALT
    )
    assert sealed.opens_to(injected_key=BY_NAME["sensor_bias"], salt_hex=SALT)
    assert not sealed.opens_to(injected_key=BY_NAME["gain_drift"], salt_hex=SALT)
    assert not sealed.opens_to(injected_key=BY_NAME["sensor_bias"], salt_hex="b" * 64)


def test_sealed_mechanism_rejects_malformed_salt() -> None:
    with pytest.raises(CausalLaboratoryError, match="64 lowercase hex"):
        SealedMechanism.commit(ontology_hash=OH, injected_key=BY_NAME["gain_drift"], salt_hex="xyz")


# --- Branch and branch-set controls ------------------------------------------------


def test_blocked_unsafe_branch_must_never_execute() -> None:
    with pytest.raises(ValidationError, match="refused, never executed"):
        Branch(
            kind=BranchKind.BLOCKED_UNSAFE,
            snapshot_hash="a" * 64,
            action_sha256="b" * 64,
            executed=True,
            settled_state_sha256="c" * 64,
        )


def test_an_executed_branch_must_record_a_settled_state() -> None:
    with pytest.raises(ValidationError, match="must record a settled state"):
        Branch(
            kind=BranchKind.NO_OP,
            snapshot_hash="a" * 64,
            action_sha256="b" * 64,
            executed=True,
            settled_state_sha256=None,
        )


def test_a_valid_branch_set_has_the_five_kinds_from_one_snapshot() -> None:
    bset = _branch_set(BY_NAME["actuator_loss"])
    assert {b.kind for b in bset.branches} == set(BranchKind)
    assert all(b.snapshot_hash == bset.snapshot.snapshot_hash for b in bset.branches)


def test_a_branch_set_missing_a_kind_is_rejected() -> None:
    bset = _branch_set(BY_NAME["actuator_loss"])
    with pytest.raises(ValidationError, match="exactly the five branch kinds"):
        BranchSet(snapshot=bset.snapshot, branches=bset.branches[:4])


def test_a_branch_set_spanning_two_snapshots_is_rejected() -> None:
    good = _branch_set(BY_NAME["actuator_loss"], snapshot=_snapshot(seed=7))
    other_snapshot = _snapshot(seed=8)
    stray = good.branches[0].model_copy(update={"snapshot_hash": other_snapshot.snapshot_hash})
    with pytest.raises(ValidationError, match="descend from the frozen snapshot"):
        BranchSet(snapshot=good.snapshot, branches=(stray, *good.branches[1:]))


# --- Hypothesis-set controls -------------------------------------------------------


def test_hypothesis_set_requires_two_known_and_the_unknown() -> None:
    hyp = _hypotheses()
    assert len(hyp.known_keys) == 2
    assert UNKNOWN_MECHANISM_KEY in hyp.candidate_keys
    with pytest.raises(ValidationError):
        LabHypothesisSet(ontology_hash=OH, known_keys=(BY_NAME["actuator_loss"],), committed_at=NOW)


def test_hypothesis_set_rejects_duplicate_and_naive_time() -> None:
    with pytest.raises(ValidationError, match="unique"):
        LabHypothesisSet(
            ontology_hash=OH,
            known_keys=(BY_NAME["actuator_loss"], BY_NAME["actuator_loss"]),
            committed_at=NOW,
        )
    with pytest.raises(ValidationError, match="timezone-aware"):
        LabHypothesisSet(
            ontology_hash=OH,
            known_keys=(BY_NAME["actuator_loss"], BY_NAME["gain_drift"]),
            committed_at=datetime(2026, 7, 17, 12, 0, 0),  # noqa: DTZ001
        )


# --- Episode-report controls (authority separation) --------------------------------


def test_a_correct_episode_binds_approved_artifacts_and_adjudicates() -> None:
    injected = BY_NAME["actuator_loss"]
    ep = _episode(injected, injected)
    result = adjudicate_episode(
        ep, injected_key=injected, salt_hex=SALT, known_ontology_keys=ONTO.known_keys
    )
    assert result.commitment_opened is True
    assert result.diagnosis_correct is True
    assert result.injected_was_unknown is False


def test_a_diagnosis_outside_the_committed_hypotheses_is_a_leak_and_rejected() -> None:
    # sensor_bias is not in the committed known set, so diagnosing it means the method saw
    # something it should not have. The episode contract refuses to bind it.
    with pytest.raises(ValidationError, match="outside the committed hypothesis set"):
        _episode(BY_NAME["actuator_loss"], BY_NAME["sensor_bias"])


def test_hypotheses_committed_after_the_episode_are_rejected() -> None:
    late = _hypotheses().model_copy(update={"committed_at": NOW + timedelta(hours=1)})
    with pytest.raises(ValidationError, match="committed after the episode"):
        _episode(BY_NAME["actuator_loss"], BY_NAME["actuator_loss"], hypothesis_set=late)


def test_episode_must_bind_the_approved_amendment_and_receipt() -> None:
    with pytest.raises(ValidationError, match="approved amendment document"):
        _episode(
            BY_NAME["actuator_loss"],
            BY_NAME["actuator_loss"],
            amendment_document_artifact_sha256="0" * 64,
        )
    with pytest.raises(ValidationError, match="owner-approval receipt"):
        _episode(
            BY_NAME["actuator_loss"], BY_NAME["actuator_loss"], owner_approval_receipt_hash="0" * 64
        )


def test_episode_ontology_must_match_sealed_and_hypotheses() -> None:
    other = SealedMechanism.commit(
        ontology_hash="0" * 64, injected_key=BY_NAME["actuator_loss"], salt_hex=SALT
    )
    with pytest.raises(ValidationError, match="sealed mechanism ontology"):
        _episode(BY_NAME["actuator_loss"], BY_NAME["actuator_loss"], sealed_mechanism=other)


# --- Adjudication controls ---------------------------------------------------------


def test_an_incorrect_diagnosis_is_adjudicated_false_not_rejected() -> None:
    # gain_drift is a committed candidate, so a wrong-but-honest diagnosis is valid to bind and
    # simply adjudicates as incorrect against the injected actuator_loss.
    injected = BY_NAME["actuator_loss"]
    ep = _episode(injected, BY_NAME["gain_drift"])
    result = adjudicate_episode(
        ep, injected_key=injected, salt_hex=SALT, known_ontology_keys=ONTO.known_keys
    )
    assert result.diagnosis_correct is False


def test_an_injected_unknown_is_adjudicated_as_unknown() -> None:
    known = (BY_NAME["actuator_loss"], BY_NAME["gain_drift"])
    hyp = _hypotheses(known)
    ep = _episode(UNKNOWN_MECHANISM_KEY, UNKNOWN_MECHANISM_KEY, hypothesis_set=hyp)
    result = adjudicate_episode(
        ep, injected_key=UNKNOWN_MECHANISM_KEY, salt_hex=SALT, known_ontology_keys=ONTO.known_keys
    )
    assert result.injected_was_unknown is True
    assert result.diagnosis_correct is True


def test_a_reveal_that_does_not_open_the_commitment_is_rejected() -> None:
    injected = BY_NAME["actuator_loss"]
    ep = _episode(injected, injected)
    with pytest.raises(CausalLaboratoryError, match="does not open the sealed"):
        adjudicate_episode(
            ep, injected_key=injected, salt_hex="b" * 64, known_ontology_keys=ONTO.known_keys
        )


def test_an_injected_key_outside_the_ontology_is_rejected() -> None:
    ep = _episode(BY_NAME["actuator_loss"], BY_NAME["actuator_loss"])
    with pytest.raises(CausalLaboratoryError, match="neither a known ontology key nor unknown"):
        adjudicate_episode(
            ep, injected_key="f" * 64, salt_hex=SALT, known_ontology_keys=ONTO.known_keys
        )


def test_naive_adjudication_time_is_rejected() -> None:
    injected = BY_NAME["actuator_loss"]
    ep = _episode(injected, injected)
    with pytest.raises(CausalLaboratoryError, match="timezone-aware"):
        adjudicate_episode(
            ep,
            injected_key=injected,
            salt_hex=SALT,
            known_ontology_keys=ONTO.known_keys,
            at=datetime(2026, 7, 17, 13, 0, 0),  # noqa: DTZ001
        )


# --- Compute-lease controls --------------------------------------------------------


def _lease(**overrides: object) -> CausalLabComputeLease:
    lease = issue_lab_compute_lease(
        KEY,
        lease_id="lab-lease-1",
        session_id="lab-sess-1",
        ontology_hash=OH,
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
        h = sha256_value(body)
        sig = KEY.sign(bytes.fromhex(h)).signature.hex()
        return CausalLabComputeLease.model_validate({**body, "lease_hash": h, "signature": sig})
    return lease


def test_committed_lease_issues_and_verifies() -> None:
    lease = _lease()
    verify_lab_compute_lease(lease, ontology_hash=OH, expected_public_key=KEY_PUB, at=NOW)
    assert lease.max_gpu_seconds == 0
    assert lease.proposal_git_commit == APPROVED_PROPOSAL_COMMIT


def test_a_widened_ceiling_fails_closed() -> None:
    lease = _lease(max_cpu_seconds=1e18)
    with pytest.raises(CausalLaboratoryError, match="approved causal-laboratory scope"):
        verify_lab_compute_lease(lease, ontology_hash=OH, expected_public_key=KEY_PUB, at=NOW)


def test_a_lease_binding_the_wrong_ontology_fails_closed() -> None:
    lease = _lease()
    with pytest.raises(CausalLaboratoryError, match="committed mechanism ontology"):
        verify_lab_compute_lease(lease, ontology_hash="0" * 64, expected_public_key=KEY_PUB, at=NOW)


def test_an_expired_lease_fails_closed() -> None:
    lease = _lease()
    with pytest.raises(CausalLaboratoryError, match="not currently valid"):
        verify_lab_compute_lease(
            lease, ontology_hash=OH, expected_public_key=KEY_PUB, at=NOW + timedelta(days=2)
        )


def test_a_forged_signature_fails_closed() -> None:
    lease = _lease().model_copy(update={"signature": "a" * 128})
    with pytest.raises(CausalLaboratoryError, match="signature mismatch"):
        verify_lab_compute_lease(lease, ontology_hash=OH, expected_public_key=KEY_PUB, at=NOW)


def test_lease_hash_forgery_is_rejected_by_the_model() -> None:
    lease = _lease()
    body = _lab_lease_body(lease)
    body["nonce"] = "f" * 64
    with pytest.raises(ValidationError, match="lease hash mismatch"):
        CausalLabComputeLease.model_validate(
            {**body, "lease_hash": lease.lease_hash, "signature": lease.signature}
        )


def test_naive_lease_verification_time_is_rejected() -> None:
    with pytest.raises(CausalLaboratoryError, match="timezone-aware"):
        verify_lab_compute_lease(
            _lease(),
            ontology_hash=OH,
            expected_public_key=KEY_PUB,
            at=datetime(2026, 7, 17, 12, 0, 0),  # noqa: DTZ001
        )


def test_a_backwards_lease_window_is_rejected() -> None:
    with pytest.raises(ValidationError, match="expiry must follow"):
        issue_lab_compute_lease(
            KEY,
            lease_id="x",
            session_id="y",
            ontology_hash=OH,
            not_before=NOW + timedelta(hours=2),
            expires_at=NOW,
            nonce="a" * 64,
        )


# --- Reference-simulator determinism -----------------------------------------------


def test_reference_simulator_is_deterministic_and_platform_stable() -> None:
    # Identical inputs must yield identical branch hashes, or paired branches are not
    # counterfactually comparable. Integer fixed-point makes this true across platforms.
    snap = _snapshot()
    b1, t1 = reference_branch(
        kind=BranchKind.TARGETED_TEST,
        snapshot=snap,
        config=CFG,
        initial_state=100,
        injected_key=BY_NAME["actuator_loss"],
        action=(500,) * 6,
    )
    b2, t2 = reference_branch(
        kind=BranchKind.TARGETED_TEST,
        snapshot=snap,
        config=CFG,
        initial_state=100,
        injected_key=BY_NAME["actuator_loss"],
        action=(500,) * 6,
    )
    assert b1.settled_state_sha256 == b2.settled_state_sha256
    assert t1 == t2


def test_a_targeted_probe_discriminates_where_a_no_op_does_not() -> None:
    snap = _snapshot()
    _, nominal_probe = reference_branch(
        kind=BranchKind.TARGETED_TEST,
        snapshot=snap,
        config=CFG,
        initial_state=100,
        injected_key="nominal-unmodeled",
        action=(500,) * 6,
    )
    _, faulted_probe = reference_branch(
        kind=BranchKind.TARGETED_TEST,
        snapshot=snap,
        config=CFG,
        initial_state=100,
        injected_key=BY_NAME["actuator_loss"],
        action=(500,) * 6,
    )
    _, nominal_quiet = reference_branch(
        kind=BranchKind.NO_OP,
        snapshot=snap,
        config=CFG,
        initial_state=100,
        injected_key="nominal-unmodeled",
        action=(0,) * 6,
    )
    _, faulted_quiet = reference_branch(
        kind=BranchKind.NO_OP,
        snapshot=snap,
        config=CFG,
        initial_state=100,
        injected_key=BY_NAME["actuator_loss"],
        action=(0,) * 6,
    )
    # The probe separates nominal from actuator loss; the no-op leaves them identical.
    assert nominal_probe != faulted_probe
    assert nominal_quiet == faulted_quiet


def test_reference_action_hash_is_order_sensitive() -> None:
    assert reference_action_hash((1, 2, 3)) != reference_action_hash((3, 2, 1))


# --- Remaining guard controls ------------------------------------------------------


def test_every_fault_mode_transforms_the_dynamics_distinctly() -> None:
    # Exercises the sensor_bias and gain_drift transforms and confirms each fault leaves a
    # distinct settled state under the same probe.
    snap = _snapshot()
    settled = {}
    for name in ("actuator_loss", "sensor_bias", "gain_drift"):
        b, _ = reference_branch(
            kind=BranchKind.TARGETED_TEST,
            snapshot=snap,
            config=CFG,
            initial_state=100,
            injected_key=BY_NAME[name],
            action=(500,) * 6,
        )
        settled[name] = b.settled_state_sha256
    assert len({*settled.values()}) == 3


def test_a_branch_set_with_a_duplicate_kind_is_rejected() -> None:
    bset = _branch_set(BY_NAME["actuator_loss"])
    dup = bset.branches[0]  # a second no_op
    with pytest.raises(ValidationError, match="at most once"):
        BranchSet(snapshot=bset.snapshot, branches=(dup, *bset.branches))


def test_hypothesis_hash_is_stable_and_definition_bound() -> None:
    a = _hypotheses()
    b = _hypotheses()
    assert a.hypothesis_hash == b.hypothesis_hash
    c = _hypotheses((BY_NAME["sensor_bias"], BY_NAME["gain_drift"]))
    assert c.hypothesis_hash != a.hypothesis_hash


def test_episode_must_bind_the_approved_machine_proposal() -> None:
    with pytest.raises(ValidationError, match="approved machine proposal"):
        _episode(
            BY_NAME["actuator_loss"],
            BY_NAME["actuator_loss"],
            machine_proposal_artifact_sha256="0" * 64,
        )


def test_episode_rejects_a_hypothesis_set_from_a_different_ontology() -> None:
    other = LabHypothesisSet(
        ontology_hash="0" * 64,
        known_keys=(BY_NAME["actuator_loss"], BY_NAME["gain_drift"]),
        committed_at=NOW,
    )
    with pytest.raises(ValidationError, match="hypothesis set ontology"):
        _episode(BY_NAME["actuator_loss"], BY_NAME["actuator_loss"], hypothesis_set=other)


def test_episode_naive_time_is_rejected() -> None:
    with pytest.raises(ValidationError, match="episode time must be timezone-aware"):
        _episode(
            BY_NAME["actuator_loss"],
            BY_NAME["actuator_loss"],
            produced_at=datetime(2026, 7, 17, 12, 30, 0),  # noqa: DTZ001
        )


def test_lease_naive_window_is_rejected_by_the_model() -> None:
    good = _lease()
    body = _lab_lease_body(good)
    body["not_before"] = "2026-07-17T12:00:00"
    with pytest.raises(ValidationError, match="timezone-aware"):
        CausalLabComputeLease.model_validate(
            {**body, "lease_hash": good.lease_hash, "signature": good.signature}
        )
