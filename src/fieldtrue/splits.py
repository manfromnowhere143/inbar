"""Leakage-resistant group split construction and validation."""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from fieldtrue.canonical import sha256_value
from fieldtrue.domain import Identifier, Sha256

SplitName = Literal["train", "validation", "test"]


class SplitInfeasibleError(ValueError):
    """Requested disjoint dimensions connect the corpus into too few components."""


class SplitUnit(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    incident_id: Identifier
    hardware_family: str
    hardware_id: str
    mission_id: str
    fault_family: str
    evidence_hash: Sha256
    truth_hash: Sha256


class SplitAssignment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    incident_id: Identifier
    split: SplitName
    component_id: Sha256


class SplitLock(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["fieldtrue.split-lock.v1"] = "fieldtrue.split-lock.v1"
    seed: str = Field(min_length=1)
    holdout_dimensions: tuple[str, ...] = Field(min_length=1)
    corpus_hash: Sha256
    assignments: tuple[SplitAssignment, ...]
    split_counts: dict[SplitName, int]

    @model_validator(mode="after")
    def lock_is_structurally_complete(self) -> Self:
        identifiers = [assignment.incident_id for assignment in self.assignments]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("split assignment incident IDs must be unique")
        if len(self.holdout_dimensions) != len(set(self.holdout_dimensions)):
            raise ValueError("holdout dimensions must be unique")
        if not set(self.holdout_dimensions).issubset(_ALLOWED_DIMENSIONS):
            raise ValueError("holdout dimensions contain unsupported values")
        observed_counts = Counter(assignment.split for assignment in self.assignments)
        required_splits: tuple[SplitName, ...] = ("train", "validation", "test")
        if any(observed_counts[split] == 0 for split in required_splits):
            raise ValueError("every split must contain at least one incident")
        if self.split_counts != {split: observed_counts[split] for split in required_splits}:
            raise ValueError("split counts do not match assignments")
        return self


class _UnionFind:
    def __init__(self, identifiers: list[str]) -> None:
        self.parent = {identifier: identifier for identifier in identifiers}

    def find(self, identifier: str) -> str:
        parent = self.parent[identifier]
        if parent != identifier:
            self.parent[identifier] = self.find(parent)
        return self.parent[identifier]

    def union(self, left: str, right: str) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            self.parent[right_root] = left_root


_ALLOWED_DIMENSIONS = {
    "hardware_family",
    "hardware_id",
    "mission_id",
    "fault_family",
}


def _components(
    units: list[SplitUnit],
    holdout_dimensions: tuple[str, ...],
) -> list[list[SplitUnit]]:
    if not units:
        raise ValueError("cannot split an empty corpus")
    if (
        not holdout_dimensions
        or len(holdout_dimensions) != len(set(holdout_dimensions))
        or not set(holdout_dimensions).issubset(_ALLOWED_DIMENSIONS)
    ):
        raise ValueError("holdout dimensions are empty or unsupported")
    union_find = _UnionFind([unit.incident_id for unit in units])
    for dimension in holdout_dimensions:
        seen: dict[str, str] = {}
        for unit in units:
            value = str(getattr(unit, dimension))
            previous = seen.setdefault(value, unit.incident_id)
            union_find.union(previous, unit.incident_id)
    grouped: dict[str, list[SplitUnit]] = defaultdict(list)
    for unit in units:
        grouped[union_find.find(unit.incident_id)].append(unit)
    return list(grouped.values())


def freeze_group_split(
    units: list[SplitUnit],
    *,
    seed: str,
    holdout_dimensions: tuple[str, ...] = ("hardware_id", "fault_family"),
    fractions: Annotated[tuple[float, float, float], Field(min_length=3, max_length=3)] = (
        0.6,
        0.2,
        0.2,
    ),
) -> SplitLock:
    if (
        len(fractions) != 3
        or any(fraction <= 0 for fraction in fractions)
        or abs(sum(fractions) - 1.0) > 1e-9
    ):
        raise ValueError("split fractions must be positive and sum to one")
    identifiers = [unit.incident_id for unit in units]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("incident IDs must be unique")

    components = _components(units, holdout_dimensions)
    if len(components) < 3:
        raise SplitInfeasibleError(
            f"{len(components)} leakage component(s) cannot populate three splits"
        )
    ordered_components = sorted(
        components,
        key=lambda component: hashlib.sha256(
            f"{seed}|{'|'.join(sorted(unit.incident_id for unit in component))}".encode()
        ).hexdigest(),
    )
    split_names: tuple[SplitName, ...] = ("train", "validation", "test")
    target_counts = {
        name: len(units) * fraction for name, fraction in zip(split_names, fractions, strict=True)
    }
    counts: dict[SplitName, int] = dict.fromkeys(split_names, 0)
    assignments: list[SplitAssignment] = []
    for component in ordered_components:
        split = min(
            split_names,
            key=lambda name: (
                counts[name] / target_counts[name],
                counts[name],
                split_names.index(name),
            ),
        )
        component_id = sha256_value(sorted(unit.incident_id for unit in component))
        for unit in sorted(component, key=lambda item: item.incident_id):
            assignments.append(
                SplitAssignment(
                    incident_id=unit.incident_id,
                    split=split,
                    component_id=component_id,
                )
            )
        counts[split] += len(component)

    lock = SplitLock(
        seed=seed,
        holdout_dimensions=holdout_dimensions,
        corpus_hash=sha256_value(
            [
                unit.model_dump(mode="json")
                for unit in sorted(units, key=lambda item: item.incident_id)
            ]
        ),
        assignments=tuple(sorted(assignments, key=lambda item: item.incident_id)),
        split_counts=counts,
    )
    validate_split_lock(lock, units)
    return lock


def validate_split_lock(lock: SplitLock, units: list[SplitUnit]) -> None:
    expected_hash = sha256_value(
        [unit.model_dump(mode="json") for unit in sorted(units, key=lambda item: item.incident_id)]
    )
    if expected_hash != lock.corpus_hash:
        raise ValueError("split lock does not match corpus content")
    assignment_by_id = {assignment.incident_id: assignment for assignment in lock.assignments}
    if set(assignment_by_id) != {unit.incident_id for unit in units}:
        raise ValueError("split lock does not cover the corpus exactly")
    components = _components(units, lock.holdout_dimensions)
    if len(components) < 3:
        raise SplitInfeasibleError(
            f"{len(components)} leakage component(s) cannot populate three splits"
        )
    for component in components:
        component_incidents = sorted(unit.incident_id for unit in component)
        expected_component_id = sha256_value(component_incidents)
        component_assignments = [assignment_by_id[incident] for incident in component_incidents]
        if len({assignment.split for assignment in component_assignments}) != 1:
            raise ValueError("one leakage component is assigned across multiple splits")
        if any(
            assignment.component_id != expected_component_id for assignment in component_assignments
        ):
            raise ValueError("split assignment component ID is incorrect")
    observed_counts = Counter(assignment.split for assignment in lock.assignments)
    split_names: tuple[SplitName, ...] = ("train", "validation", "test")
    expected_counts: dict[SplitName, int] = {split: observed_counts[split] for split in split_names}
    if lock.split_counts != expected_counts:
        raise ValueError("split counts do not match assignments")
    if any(expected_counts[split] == 0 for split in split_names):
        raise ValueError("every split must contain at least one incident")
    values_by_split: dict[str, dict[SplitName, set[str]]] = {
        dimension: {"train": set(), "validation": set(), "test": set()}
        for dimension in lock.holdout_dimensions
    }
    unit_by_id = {unit.incident_id: unit for unit in units}
    for incident_id, assignment in assignment_by_id.items():
        unit = unit_by_id[incident_id]
        for dimension in lock.holdout_dimensions:
            values_by_split[dimension][assignment.split].add(str(getattr(unit, dimension)))
    for dimension, by_split in values_by_split.items():
        for index, left in enumerate(("train", "validation", "test")):
            for right in ("train", "validation", "test")[index + 1 :]:
                overlap = by_split[left] & by_split[right]  # type: ignore[index]
                if overlap:
                    raise ValueError(
                        f"{dimension} leaks between {left} and {right}: {sorted(overlap)}"
                    )


def leakage_component_count(
    units: list[SplitUnit],
    holdout_dimensions: tuple[str, ...] = ("hardware_id", "fault_family"),
) -> int:
    """Return the independently assignable group count for readiness checks."""

    return len(_components(units, holdout_dimensions))
