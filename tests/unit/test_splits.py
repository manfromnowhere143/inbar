from __future__ import annotations

import pytest

from fieldtrue.splits import (
    SplitInfeasibleError,
    SplitLock,
    SplitUnit,
    freeze_group_split,
    leakage_component_count,
    validate_split_lock,
)
from tests.helpers import HASH_A, HASH_B


def _unit(index: int, hardware: str, fault: str) -> SplitUnit:
    return SplitUnit(
        incident_id=f"incident-{index}",
        hardware_family=f"family-{hardware}",
        hardware_id=hardware,
        mission_id=f"mission-{index}",
        fault_family=fault,
        evidence_hash=HASH_A,
        truth_hash=HASH_B,
    )


def test_split_is_deterministic_and_disjoint_on_every_requested_dimension() -> None:
    units = [
        _unit(1, "h1", "f1"),
        _unit(2, "h2", "f2"),
        _unit(3, "h3", "f3"),
        _unit(4, "h4", "f4"),
        _unit(5, "h5", "f5"),
        _unit(6, "h6", "f6"),
    ]
    first = freeze_group_split(units, seed="frozen-seed")
    second = freeze_group_split(list(reversed(units)), seed="frozen-seed")
    assert first == second
    assert all(first.split_counts[name] > 0 for name in ("train", "validation", "test"))
    validate_split_lock(first, units)


def test_shared_holdout_values_form_one_leakage_component() -> None:
    units = [
        _unit(1, "shared", "f1"),
        _unit(2, "shared", "f2"),
        _unit(3, "shared", "f3"),
    ]
    with pytest.raises(SplitInfeasibleError, match="component"):
        freeze_group_split(units, seed="seed")


def test_split_lock_rejects_changed_corpus() -> None:
    units = [_unit(1, "h1", "f1"), _unit(2, "h2", "f2"), _unit(3, "h3", "f3")]
    lock = freeze_group_split(units, seed="seed")
    changed = [*units[:-1], _unit(3, "h3", "changed")]
    with pytest.raises(ValueError, match="content"):
        validate_split_lock(lock, changed)


def test_duplicate_incident_ids_are_rejected() -> None:
    unit = _unit(1, "h1", "f1")
    with pytest.raises(ValueError, match="unique"):
        freeze_group_split([unit, unit, _unit(2, "h2", "f2")], seed="seed")


def test_split_validation_recomputes_counts_components_and_nonempty_splits() -> None:
    units = [
        _unit(1, "h1", "f1"),
        _unit(2, "h2", "f2"),
        _unit(3, "h3", "f3"),
    ]
    lock = freeze_group_split(units, seed="seed")
    forged_components = lock.model_copy(
        update={
            "assignments": tuple(
                assignment.model_copy(update={"component_id": HASH_A})
                for assignment in lock.assignments
            )
        }
    )
    with pytest.raises(ValueError, match="component ID"):
        validate_split_lock(forged_components, units)

    all_train_assignments = tuple(
        assignment.model_copy(update={"split": "train"}) for assignment in lock.assignments
    )
    all_train = SplitLock.model_construct(
        schema_version=lock.schema_version,
        seed=lock.seed,
        holdout_dimensions=lock.holdout_dimensions,
        corpus_hash=lock.corpus_hash,
        assignments=all_train_assignments,
        split_counts={"train": 3, "validation": 0, "test": 0},
    )
    with pytest.raises(ValueError, match="every split"):
        validate_split_lock(all_train, units)


def test_connected_hardware_fault_graph_exposes_transfer_infeasibility() -> None:
    units = [
        _unit(1, "h1", "shared"),
        _unit(2, "h2", "shared"),
        _unit(3, "h2", "f2"),
        _unit(4, "h3", "f2"),
    ]
    assert leakage_component_count(units) == 1
    with pytest.raises(SplitInfeasibleError):
        freeze_group_split(units, seed="seed")
