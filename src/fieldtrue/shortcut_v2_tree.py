"""Exact deterministic tree authority for Shortcut Authority V2.

The implementation is deliberately independent of statistical and numeric libraries. All
scientific decisions are functions of immutable typed inputs, integer arithmetic, exact rational
Gini values, and repository canonical JSON bytes.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from fractions import Fraction
from itertools import pairwise
from typing import Annotated, Final, Literal, TypeAlias, TypeVar

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictStr,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

from fieldtrue.canonical import canonical_json, sha256_value
from fieldtrue.domain import Identifier, Sha256
from fieldtrue.shortcut_v2_hashing import incident_id_list_sha256

MAX_FEATURES: Final = 4_096
MAX_PREDICATES_PER_NODE: Final = 100_000
MINIMUM_CHILD_INCIDENTS: Final = 2
MAXIMUM_DEPTH: Final = 2

_PREDICATE_SCHEMA_VERSION: Final = "inbar.iter001.tree-predicate.v1"
_FEATURE_DEFINITION_ROOT_DOMAIN: Final = "inbar.iter001.tree-feature-definition-root.v1"
_DECIMAL_PATTERN = re.compile(r"^-?(0|[1-9][0-9]*)(?:\.([0-9]+))?$")
_PREDICTION_KEY_PATTERN = re.compile(r"^(?:unknown|[0-9a-f]{64})$")
_DECIMAL_CHUNK_DIGITS: Final = 9
_DECIMAL_CHUNK_BASE: Final = 10**_DECIMAL_CHUNK_DIGITS

CanonicalDecimalString = Annotated[
    str,
    StringConstraints(pattern=r"^-?(0|[1-9][0-9]*)(\.[0-9]+)?$"),
]
PredictionKey = Annotated[
    str,
    StringConstraints(pattern=r"^(?:unknown|[0-9a-f]{64})$"),
]
FeatureType = Literal["boolean", "numeric", "categorical"]


class ShortcutTreeError(ValueError):
    """A tree input or supplied tree state violates the frozen algorithm."""


class ShortcutTreeCapacityError(ShortcutTreeError):
    """A frozen feature or predicate ceiling was exceeded."""


class ShortcutTreeValidationError(ShortcutTreeError):
    """A supplied tree differs from deterministic recomputation."""


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


_ModelT = TypeVar("_ModelT", bound=_StrictFrozenModel)


def _strict_revalidate(value: _ModelT, model_type: type[_ModelT], *, label: str) -> _ModelT:
    try:
        return model_type.model_validate(value.model_dump(mode="python"), strict=True)
    except ValidationError as error:
        raise ShortcutTreeValidationError(f"{label} failed strict revalidation") from error


def _parse_unbounded_decimal_digits(digits: str) -> int:
    value = 0
    for offset in range(0, len(digits), _DECIMAL_CHUNK_DIGITS):
        chunk = digits[offset : offset + _DECIMAL_CHUNK_DIGITS]
        value = value * (10 ** len(chunk)) + int(chunk)
    return value


def _render_unbounded_decimal_digits(value: int) -> str:
    if value == 0:
        return "0"
    chunks: list[int] = []
    while value:
        value, remainder = divmod(value, _DECIMAL_CHUNK_BASE)
        chunks.append(remainder)
    return str(chunks[-1]) + "".join(f"{chunk:09d}" for chunk in reversed(chunks[:-1]))


def parse_canonical_decimal(value: str) -> Fraction:
    """Parse one finite canonical decimal without a finite arithmetic context."""

    if not isinstance(value, str):
        raise ShortcutTreeError("canonical decimal must be a string")
    match = _DECIMAL_PATTERN.fullmatch(value)
    if match is None:
        raise ShortcutTreeError("numeric feature is not a canonical decimal")
    fractional = match.group(2)
    if value.startswith("-0") and (fractional is None or set(fractional) <= {"0"}):
        raise ShortcutTreeError("zero has only the canonical representation 0")
    if fractional is not None and fractional.endswith("0"):
        raise ShortcutTreeError("canonical decimal cannot end in a fractional zero")

    negative = value.startswith("-")
    unsigned = value[1:] if negative else value
    whole, separator, fraction = unsigned.partition(".")
    scale = len(fraction) if separator else 0
    coefficient = _parse_unbounded_decimal_digits(whole + fraction)
    if negative:
        coefficient = -coefficient
    return Fraction(coefficient, 10**scale)


def canonical_decimal(value: Fraction) -> str:
    """Serialize an exactly finite rational as the unique canonical decimal string."""

    denominator = value.denominator
    twos = 0
    fives = 0
    while denominator % 2 == 0:
        denominator //= 2
        twos += 1
    while denominator % 5 == 0:
        denominator //= 5
        fives += 1
    if denominator != 1:
        raise ShortcutTreeError("rational does not have a finite decimal representation")
    if value.numerator == 0:
        return "0"

    scale = max(twos, fives)
    scaled = abs(value.numerator) * (2 ** (scale - twos)) * (5 ** (scale - fives))
    digits = _render_unbounded_decimal_digits(scaled)
    if scale:
        digits = digits.rjust(scale + 1, "0")
        rendered = f"{digits[:-scale]}.{digits[-scale:]}"
        rendered = rendered.rstrip("0").rstrip(".")
    else:
        rendered = digits
    return f"-{rendered}" if value.numerator < 0 else rendered


def exact_midpoint(left: str, right: str) -> str:
    """Return the canonical arithmetic mean of two distinct ordered decimals."""

    left_value = parse_canonical_decimal(left)
    right_value = parse_canonical_decimal(right)
    if left_value >= right_value:
        raise ShortcutTreeError("numeric midpoint endpoints must be strictly ordered")
    return canonical_decimal((left_value + right_value) / 2)


class MissingFeatureValue(_StrictFrozenModel):
    kind: Literal["missing"]
    feature_type: FeatureType


class BooleanFeatureValue(_StrictFrozenModel):
    kind: Literal["boolean"]
    value: StrictBool


class NumericFeatureValue(_StrictFrozenModel):
    kind: Literal["numeric"]
    value: CanonicalDecimalString

    @field_validator("value")
    @classmethod
    def value_is_canonical(cls, value: str) -> str:
        parse_canonical_decimal(value)
        return value


class CategoricalFeatureValue(_StrictFrozenModel):
    kind: Literal["categorical"]
    value: StrictStr

    @field_validator("value")
    @classmethod
    def value_is_utf8(cls, value: str) -> str:
        return _canonical_utf8(value)


FeatureValue: TypeAlias = Annotated[
    MissingFeatureValue | BooleanFeatureValue | NumericFeatureValue | CategoricalFeatureValue,
    Field(discriminator="kind"),
]


def feature_value_type(value: FeatureValue) -> FeatureType:
    if isinstance(value, MissingFeatureValue):
        return value.feature_type
    return value.kind


class FeatureEntry(_StrictFrozenModel):
    feature_key: Sha256
    value: FeatureValue


class FeatureVector(_StrictFrozenModel):
    incident_id: Identifier
    entries: tuple[FeatureEntry, ...]

    @model_validator(mode="after")
    def entries_are_canonical(self) -> FeatureVector:
        keys = tuple(entry.feature_key for entry in self.entries)
        if keys != tuple(sorted(keys, key=lambda item: item.encode("utf-8"))):
            raise ValueError("feature entries must be sorted by feature key")
        if len(keys) != len(set(keys)):
            raise ValueError("feature vector contains duplicate feature keys")
        return self


class FeatureDefinition(_StrictFrozenModel):
    feature_key: Sha256
    feature_type: FeatureType


class IsMissingPredicate(_StrictFrozenModel):
    schema_version: Literal["inbar.iter001.tree-predicate.v1"]
    feature_key: Sha256
    operator: Literal["is_missing"]
    operand: None


class EqualsBooleanPredicate(_StrictFrozenModel):
    schema_version: Literal["inbar.iter001.tree-predicate.v1"]
    feature_key: Sha256
    operator: Literal["equals_boolean"]
    operand: StrictBool


class EqualsCategoricalPredicate(_StrictFrozenModel):
    schema_version: Literal["inbar.iter001.tree-predicate.v1"]
    feature_key: Sha256
    operator: Literal["equals_categorical"]
    operand: StrictStr

    @field_validator("operand")
    @classmethod
    def operand_is_utf8(cls, value: str) -> str:
        return _canonical_utf8(value)


class LessThanOrEqualNumericPredicate(_StrictFrozenModel):
    schema_version: Literal["inbar.iter001.tree-predicate.v1"]
    feature_key: Sha256
    operator: Literal["less_than_or_equal_numeric"]
    operand: CanonicalDecimalString

    @field_validator("operand")
    @classmethod
    def operand_is_canonical(cls, value: str) -> str:
        parse_canonical_decimal(value)
        return value


TreePredicate: TypeAlias = Annotated[
    IsMissingPredicate
    | EqualsBooleanPredicate
    | EqualsCategoricalPredicate
    | LessThanOrEqualNumericPredicate,
    Field(discriminator="operator"),
]


def predicate_bytes(predicate: TreePredicate) -> bytes:
    """Return the exact unsigned byte key used for equal-Gini ties."""

    validated = _strict_revalidate(predicate, type(predicate), label="tree predicate")
    return canonical_json(validated.model_dump(mode="json"))


class ExactRational(_StrictFrozenModel):
    numerator: int = Field(ge=0)
    denominator: int = Field(gt=0)

    @model_validator(mode="after")
    def fraction_is_reduced(self) -> ExactRational:
        if math.gcd(self.numerator, self.denominator) != 1:
            raise ValueError("exact rational must be reduced")
        return self

    @classmethod
    def from_fraction(cls, value: Fraction) -> ExactRational:
        if value < 0:
            raise ShortcutTreeError("tree impurity cannot be negative")
        return cls(numerator=value.numerator, denominator=value.denominator)

    def as_fraction(self) -> Fraction:
        return Fraction(self.numerator, self.denominator)


class ClassCount(_StrictFrozenModel):
    prediction_key: PredictionKey
    count: int = Field(gt=0)


def exact_gini(counts: Mapping[str, int]) -> Fraction:
    """Compute Gini impurity from positive integer class counts."""

    if not counts or any(
        not isinstance(count, int) or isinstance(count, bool) or count <= 0
        for count in counts.values()
    ):
        raise ShortcutTreeError("Gini requires positive integer class counts")
    total = sum(counts.values())
    return Fraction(1, 1) - sum(
        (Fraction(count, total) ** 2 for count in counts.values()),
        start=Fraction(0, 1),
    )


def weighted_gini(
    false_counts: Mapping[str, int],
    true_counts: Mapping[str, int],
) -> Fraction:
    """Compute exact child-size-weighted Gini impurity."""

    false_total = sum(false_counts.values())
    true_total = sum(true_counts.values())
    if false_total <= 0 or true_total <= 0:
        raise ShortcutTreeError("weighted Gini requires two nonempty children")
    total = false_total + true_total
    return (false_total * exact_gini(false_counts) + true_total * exact_gini(true_counts)) / total


def _class_count_tuple(counts: Mapping[str, int]) -> tuple[ClassCount, ...]:
    return tuple(
        ClassCount(prediction_key=key, count=count)
        for key, count in sorted(counts.items(), key=lambda item: item[0].encode("utf-8"))
    )


def _counts_from_models(counts: Sequence[ClassCount]) -> dict[str, int]:
    return {item.prediction_key: item.count for item in counts}


def _incident_root(incident_ids: Sequence[str]) -> str:
    return incident_id_list_sha256(incident_ids)


def _feature_definition_root(definitions: Sequence[FeatureDefinition]) -> str:
    return sha256_value(
        {
            "domain": _FEATURE_DEFINITION_ROOT_DOMAIN,
            "items": [item.model_dump(mode="json") for item in definitions],
        }
    )


def _canonical_utf8(value: str) -> str:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError("categorical value is not valid canonical UTF-8") from error
    return value


def _validate_feature_definitions(
    definitions: Sequence[FeatureDefinition],
) -> tuple[FeatureDefinition, ...]:
    frozen = tuple(definitions)
    keys = tuple(item.feature_key for item in frozen)
    if keys != tuple(sorted(keys, key=lambda item: item.encode("utf-8"))):
        raise ShortcutTreeError("feature definitions must be canonically ordered")
    if len(keys) != len(set(keys)):
        raise ShortcutTreeError("feature definitions contain duplicate keys")
    if len(keys) > MAX_FEATURES:
        raise ShortcutTreeCapacityError("feature count exceeds 4096")
    return frozen


class _TreeElementState(_StrictFrozenModel):
    depth: int = Field(ge=0, le=MAXIMUM_DEPTH)
    train_incident_ids: tuple[Identifier, ...] = Field(min_length=1)
    train_incident_ids_sha256: Sha256
    class_counts: tuple[ClassCount, ...] = Field(min_length=1)
    impurity: ExactRational

    @model_validator(mode="after")
    def statistics_are_derived(self) -> _TreeElementState:
        identifiers = self.train_incident_ids
        if identifiers != tuple(sorted(identifiers, key=lambda item: item.encode("utf-8"))):
            raise ValueError("tree incident IDs must be canonically ordered")
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("tree element contains duplicate incidents")
        if self.train_incident_ids_sha256 != _incident_root(identifiers):
            raise ValueError("tree incident root does not match its incidents")
        keys = tuple(item.prediction_key for item in self.class_counts)
        if keys != tuple(sorted(keys, key=lambda item: item.encode("utf-8"))):
            raise ValueError("tree class counts must be canonically ordered")
        if len(keys) != len(set(keys)):
            raise ValueError("tree class counts contain duplicate keys")
        counts = _counts_from_models(self.class_counts)
        if sum(counts.values()) != len(identifiers):
            raise ValueError("tree class counts do not cover its incidents")
        if self.impurity.as_fraction() != exact_gini(counts):
            raise ValueError("tree impurity does not follow from class counts")
        return self


class TreeLeaf(_TreeElementState):
    kind: Literal["leaf"]
    prediction_key: PredictionKey | None
    abstention_reason: Literal["class_tie"] | None

    @model_validator(mode="after")
    def output_is_modal(self) -> TreeLeaf:
        counts = _counts_from_models(self.class_counts)
        maximum = max(counts.values())
        winners = [key for key, count in counts.items() if count == maximum]
        expected_key = winners[0] if len(winners) == 1 else None
        expected_reason = None if expected_key is not None else "class_tie"
        if self.prediction_key != expected_key or self.abstention_reason != expected_reason:
            raise ValueError("leaf output does not follow from its unique modal class")
        return self


class DepthOneTreeNode(_TreeElementState):
    kind: Literal["node"]
    depth: Literal[1]
    predicate: TreePredicate
    split_impurity: ExactRational
    false_child: TreeLeaf
    true_child: TreeLeaf

    @model_validator(mode="after")
    def node_is_exact(self) -> DepthOneTreeNode:
        _validate_node(self, expected_child_depth=2)
        return self


DepthOneChild: TypeAlias = Annotated[
    TreeLeaf | DepthOneTreeNode,
    Field(discriminator="kind"),
]


class TreeRootNode(_TreeElementState):
    kind: Literal["node"]
    depth: Literal[0]
    predicate: TreePredicate
    split_impurity: ExactRational
    false_child: DepthOneChild
    true_child: DepthOneChild

    @model_validator(mode="after")
    def node_is_exact(self) -> TreeRootNode:
        _validate_node(self, expected_child_depth=1)
        return self


TreeRoot: TypeAlias = Annotated[TreeLeaf | TreeRootNode, Field(discriminator="kind")]
TreeElement: TypeAlias = TreeLeaf | DepthOneTreeNode | TreeRootNode
TreeNode: TypeAlias = DepthOneTreeNode | TreeRootNode


def _validate_node(node: TreeNode, *, expected_child_depth: int) -> None:
    children = (node.false_child, node.true_child)
    if any(child.depth != expected_child_depth for child in children):
        raise ValueError("tree child is at the wrong depth")
    if any(len(child.train_incident_ids) < MINIMUM_CHILD_INCIDENTS for child in children):
        raise ValueError("tree split violates the minimum child size")
    false_ids = set(node.false_child.train_incident_ids)
    true_ids = set(node.true_child.train_incident_ids)
    if false_ids & true_ids or false_ids | true_ids != set(node.train_incident_ids):
        raise ValueError("tree children do not exactly partition parent incidents")

    child_counts: Counter[str] = Counter()
    for child in children:
        child_counts.update(_counts_from_models(child.class_counts))
    if dict(child_counts) != _counts_from_models(node.class_counts):
        raise ValueError("tree child class counts do not aggregate to the parent")
    expected_split = (
        len(node.false_child.train_incident_ids) * node.false_child.impurity.as_fraction()
        + len(node.true_child.train_incident_ids) * node.true_child.impurity.as_fraction()
    ) / len(node.train_incident_ids)
    if node.split_impurity.as_fraction() != expected_split:
        raise ValueError("tree split impurity does not follow from its children")
    if node.split_impurity.as_fraction() >= node.impurity.as_fraction():
        raise ValueError("tree split does not strictly improve parent impurity")


class DepthTwoExactGiniTree(_StrictFrozenModel):
    schema_version: Literal["inbar.iter001.depth-two-exact-gini-tree.v1"]
    algorithm: Literal["depth_two_exact_gini_tree"]
    maximum_depth: Literal[2]
    minimum_child_incidents: Literal[2]
    feature_definitions: tuple[FeatureDefinition, ...]
    feature_root_sha256: Sha256
    train_incident_ids: tuple[Identifier, ...] = Field(min_length=1)
    train_incident_ids_sha256: Sha256
    root: TreeRoot

    @model_validator(mode="after")
    def tree_is_bound_and_depth_limited(self) -> DepthTwoExactGiniTree:
        definitions = self.feature_definitions
        keys = tuple(item.feature_key for item in definitions)
        if keys != tuple(sorted(keys, key=lambda item: item.encode("utf-8"))):
            raise ValueError("tree feature definitions must be canonically ordered")
        if len(keys) != len(set(keys)):
            raise ValueError("tree feature definitions contain duplicate keys")
        if len(keys) > MAX_FEATURES:
            raise ValueError("tree exceeds the frozen feature ceiling")
        if self.feature_root_sha256 != _feature_definition_root(definitions):
            raise ValueError("tree feature root does not match its definitions")
        if self.train_incident_ids != tuple(
            sorted(self.train_incident_ids, key=lambda item: item.encode("utf-8"))
        ):
            raise ValueError("tree train incidents must be canonically ordered")
        if len(self.train_incident_ids) != len(set(self.train_incident_ids)):
            raise ValueError("tree train incidents contain duplicates")
        if self.train_incident_ids_sha256 != _incident_root(self.train_incident_ids):
            raise ValueError("tree train incident root is incorrect")
        if self.root.depth != 0 or self.root.train_incident_ids != self.train_incident_ids:
            raise ValueError("tree root does not bind the complete train incident set")

        feature_types = {item.feature_key: item.feature_type for item in definitions}
        for element in _walk_tree(self.root):
            if isinstance(element, (DepthOneTreeNode, TreeRootNode)):
                feature_type = feature_types.get(element.predicate.feature_key)
                if feature_type is None:
                    raise ValueError("tree predicate names an absent feature")
                if not _predicate_supports_type(element.predicate, feature_type):
                    raise ValueError("tree predicate operator disagrees with feature type")
        return self


class TreePrediction(_StrictFrozenModel):
    schema_version: Literal["inbar.iter001.tree-prediction.v1"]
    incident_id: Identifier
    proposed_prediction_key: PredictionKey | None
    selected_prediction_key: PredictionKey | None
    selected_hypothesis_id: Identifier | None
    abstention_reason: Literal["class_tie", "key_unavailable"] | None
    predicates_evaluated: tuple[TreePredicate, ...] = Field(max_length=MAXIMUM_DEPTH)
    feature_keys_read: tuple[Sha256, ...] = Field(max_length=MAXIMUM_DEPTH)
    leaf_depth: int = Field(ge=0, le=MAXIMUM_DEPTH)

    @model_validator(mode="after")
    def prediction_state_is_consistent(self) -> TreePrediction:
        if len(self.predicates_evaluated) != self.leaf_depth:
            raise ValueError("prediction trace length differs from leaf depth")
        if self.feature_keys_read != tuple(
            predicate.feature_key for predicate in self.predicates_evaluated
        ):
            raise ValueError("prediction feature reads differ from its predicate trace")
        if self.abstention_reason == "class_tie":
            valid = (
                self.proposed_prediction_key is None
                and self.selected_prediction_key is None
                and self.selected_hypothesis_id is None
            )
        elif self.abstention_reason == "key_unavailable":
            valid = (
                self.proposed_prediction_key is not None
                and self.selected_prediction_key is None
                and self.selected_hypothesis_id is None
            )
        elif self.abstention_reason is None:
            valid = (
                self.proposed_prediction_key is not None
                and self.selected_prediction_key == self.proposed_prediction_key
                and self.selected_hypothesis_id is not None
            )
        else:  # pragma: no cover - Literal plus strict validation makes this unreachable.
            valid = False
        if not valid:
            raise ValueError("prediction selection does not follow from its abstention state")
        return self


def _predicate_supports_type(predicate: TreePredicate, feature_type: FeatureType) -> bool:
    if isinstance(predicate, IsMissingPredicate):
        return True
    if isinstance(predicate, EqualsBooleanPredicate):
        return feature_type == "boolean"
    if isinstance(predicate, EqualsCategoricalPredicate):
        return feature_type == "categorical"
    return feature_type == "numeric"


def _walk_tree(root: TreeRoot) -> tuple[TreeElement, ...]:
    elements: list[TreeElement] = [root]
    if isinstance(root, TreeRootNode):
        for child in (root.false_child, root.true_child):
            elements.append(child)
            if isinstance(child, DepthOneTreeNode):
                elements.extend((child.false_child, child.true_child))
    return tuple(elements)


def _feature_map(row: FeatureVector) -> dict[str, FeatureValue]:
    return {entry.feature_key: entry.value for entry in row.entries}


def _feature_definitions(rows: Sequence[FeatureVector]) -> tuple[FeatureDefinition, ...]:
    if not rows:
        raise ShortcutTreeError("tree fit requires at least one training incident")
    first = rows[0]
    if len(first.entries) > MAX_FEATURES:
        raise ShortcutTreeCapacityError("feature count exceeds 4096")
    definitions = tuple(
        FeatureDefinition(
            feature_key=entry.feature_key,
            feature_type=feature_value_type(entry.value),
        )
        for entry in first.entries
    )
    expected = tuple((item.feature_key, item.feature_type) for item in definitions)
    for row in rows[1:]:
        if len(row.entries) > MAX_FEATURES:
            raise ShortcutTreeCapacityError("feature count exceeds 4096")
        observed = tuple(
            (entry.feature_key, feature_value_type(entry.value)) for entry in row.entries
        )
        if observed != expected:
            raise ShortcutTreeError("training feature vectors do not share one typed feature union")
    return definitions


def _validate_prediction_key(value: object) -> str:
    if not isinstance(value, str) or _PREDICTION_KEY_PATTERN.fullmatch(value) is None:
        raise ShortcutTreeError("target is not a canonical shared prediction key")
    return value


def _predicate_matches(predicate: TreePredicate, value: FeatureValue) -> bool:
    if isinstance(predicate, IsMissingPredicate):
        return isinstance(value, MissingFeatureValue)
    if isinstance(value, MissingFeatureValue):
        return False
    if isinstance(predicate, EqualsBooleanPredicate):
        if not isinstance(value, BooleanFeatureValue):
            raise ShortcutTreeError("Boolean predicate received a differently typed feature")
        return value.value is predicate.operand
    if isinstance(predicate, EqualsCategoricalPredicate):
        if not isinstance(value, CategoricalFeatureValue):
            raise ShortcutTreeError("categorical predicate received a differently typed feature")
        return value.value == predicate.operand
    if not isinstance(value, NumericFeatureValue):
        raise ShortcutTreeError("numeric predicate received a differently typed feature")
    return parse_canonical_decimal(value.value) <= parse_canonical_decimal(predicate.operand)


def enumerate_predicates(
    rows: Sequence[FeatureVector],
    feature_definitions: Sequence[FeatureDefinition] | None = None,
) -> tuple[TreePredicate, ...]:
    """Enumerate the exact node-local predicate set and enforce its frozen ceiling."""

    validated_rows = tuple(
        _strict_revalidate(row, FeatureVector, label="predicate-enumeration row") for row in rows
    )
    ordered_rows = tuple(sorted(validated_rows, key=lambda item: item.incident_id.encode("utf-8")))
    if not ordered_rows:
        raise ShortcutTreeError("predicate enumeration requires at least one node incident")
    definitions = _validate_feature_definitions(
        tuple(
            _strict_revalidate(
                definition,
                FeatureDefinition,
                label="predicate feature definition",
            )
            for definition in feature_definitions
        )
        if feature_definitions is not None
        else _feature_definitions(ordered_rows)
    )
    expected_union = tuple(
        (definition.feature_key, definition.feature_type) for definition in definitions
    )
    for row in ordered_rows:
        observed_union = tuple(
            (entry.feature_key, feature_value_type(entry.value)) for entry in row.entries
        )
        if observed_union != expected_union:
            raise ShortcutTreeError(
                "node rows do not exactly match the supplied typed feature union"
            )
    maps = tuple(_feature_map(row) for row in ordered_rows)
    candidates: list[TreePredicate] = []

    def append(predicate: TreePredicate) -> None:
        if len(candidates) == MAX_PREDICATES_PER_NODE:
            raise ShortcutTreeCapacityError("candidate predicate count exceeds 100000")
        candidates.append(predicate)

    for definition in definitions:
        values: list[FeatureValue] = []
        for values_by_key in maps:
            try:
                value = values_by_key[definition.feature_key]
            except KeyError as error:
                raise ShortcutTreeError("node row is missing a feature-union entry") from error
            if feature_value_type(value) != definition.feature_type:
                raise ShortcutTreeError("node feature value disagrees with its declared type")
            values.append(value)

        append(
            IsMissingPredicate(
                schema_version=_PREDICATE_SCHEMA_VERSION,
                feature_key=definition.feature_key,
                operator="is_missing",
                operand=None,
            )
        )
        if definition.feature_type == "boolean":
            append(
                EqualsBooleanPredicate(
                    schema_version=_PREDICATE_SCHEMA_VERSION,
                    feature_key=definition.feature_key,
                    operator="equals_boolean",
                    operand=False,
                )
            )
            append(
                EqualsBooleanPredicate(
                    schema_version=_PREDICATE_SCHEMA_VERSION,
                    feature_key=definition.feature_key,
                    operator="equals_boolean",
                    operand=True,
                )
            )
        elif definition.feature_type == "categorical":
            distinct = sorted(
                {value.value for value in values if isinstance(value, CategoricalFeatureValue)},
                key=lambda item: item.encode("utf-8"),
            )
            for item in distinct:
                append(
                    EqualsCategoricalPredicate(
                        schema_version=_PREDICATE_SCHEMA_VERSION,
                        feature_key=definition.feature_key,
                        operator="equals_categorical",
                        operand=item,
                    )
                )
        else:
            numeric = sorted(
                {
                    parse_canonical_decimal(value.value)
                    for value in values
                    if isinstance(value, NumericFeatureValue)
                }
            )
            for left, right in pairwise(numeric):
                append(
                    LessThanOrEqualNumericPredicate(
                        schema_version=_PREDICATE_SCHEMA_VERSION,
                        feature_key=definition.feature_key,
                        operator="less_than_or_equal_numeric",
                        operand=canonical_decimal((left + right) / 2),
                    )
                )
    return tuple(sorted(candidates, key=predicate_bytes))


class _TrainingExample:
    __slots__ = ("features", "incident_id", "row", "target")

    def __init__(self, row: FeatureVector, target: str) -> None:
        self.row = row
        self.incident_id = row.incident_id
        self.features = _feature_map(row)
        self.target = target


def _element_statistics(
    examples: Sequence[_TrainingExample],
) -> tuple[tuple[str, ...], tuple[ClassCount, ...], ExactRational]:
    identifiers = tuple(
        sorted((item.incident_id for item in examples), key=lambda item: item.encode("utf-8"))
    )
    counts = Counter(item.target for item in examples)
    return identifiers, _class_count_tuple(counts), ExactRational.from_fraction(exact_gini(counts))


def _leaf(examples: Sequence[_TrainingExample], depth: int) -> TreeLeaf:
    identifiers, class_counts, impurity = _element_statistics(examples)
    counts = _counts_from_models(class_counts)
    maximum = max(counts.values())
    winners = [key for key, count in counts.items() if count == maximum]
    prediction_key = winners[0] if len(winners) == 1 else None
    return TreeLeaf(
        kind="leaf",
        depth=depth,
        train_incident_ids=identifiers,
        train_incident_ids_sha256=_incident_root(identifiers),
        class_counts=class_counts,
        impurity=impurity,
        prediction_key=prediction_key,
        abstention_reason=None if prediction_key is not None else "class_tie",
    )


def _fit_element(
    examples: Sequence[_TrainingExample],
    definitions: tuple[FeatureDefinition, ...],
    depth: int,
) -> TreeElement:
    if depth == MAXIMUM_DEPTH:
        return _leaf(examples, depth)

    identifiers, class_counts, impurity = _element_statistics(examples)
    rows = tuple(item.row for item in examples)
    candidates = enumerate_predicates(rows, definitions)
    best: (
        tuple[
            Fraction,
            bytes,
            TreePredicate,
            tuple[_TrainingExample, ...],
            tuple[_TrainingExample, ...],
        ]
        | None
    ) = None
    for predicate in candidates:
        false_examples: list[_TrainingExample] = []
        true_examples: list[_TrainingExample] = []
        for example in examples:
            destination = (
                true_examples
                if _predicate_matches(predicate, example.features[predicate.feature_key])
                else false_examples
            )
            destination.append(example)
        if (
            len(false_examples) < MINIMUM_CHILD_INCIDENTS
            or len(true_examples) < MINIMUM_CHILD_INCIDENTS
        ):
            continue
        false_counts = Counter(item.target for item in false_examples)
        true_counts = Counter(item.target for item in true_examples)
        score = weighted_gini(false_counts, true_counts)
        candidate = (
            score,
            predicate_bytes(predicate),
            predicate,
            tuple(false_examples),
            tuple(true_examples),
        )
        if best is None or candidate[:2] < best[:2]:
            best = candidate

    if best is None or best[0] >= impurity.as_fraction():
        return _leaf(examples, depth)
    score, _, predicate, best_false_examples, best_true_examples = best
    false_child = _fit_element(best_false_examples, definitions, depth + 1)
    true_child = _fit_element(best_true_examples, definitions, depth + 1)
    split_impurity = ExactRational.from_fraction(score)
    if depth == 0:
        if not isinstance(false_child, (TreeLeaf, DepthOneTreeNode)) or not isinstance(
            true_child, (TreeLeaf, DepthOneTreeNode)
        ):
            raise ShortcutTreeError("root produced a child at the wrong depth")
        return TreeRootNode(
            kind="node",
            depth=0,
            train_incident_ids=identifiers,
            train_incident_ids_sha256=_incident_root(identifiers),
            class_counts=class_counts,
            impurity=impurity,
            predicate=predicate,
            split_impurity=split_impurity,
            false_child=false_child,
            true_child=true_child,
        )
    if not isinstance(false_child, TreeLeaf) or not isinstance(true_child, TreeLeaf):
        raise ShortcutTreeError("depth-one node produced a child beyond maximum depth")
    return DepthOneTreeNode(
        kind="node",
        depth=1,
        train_incident_ids=identifiers,
        train_incident_ids_sha256=_incident_root(identifiers),
        class_counts=class_counts,
        impurity=impurity,
        predicate=predicate,
        split_impurity=split_impurity,
        false_child=false_child,
        true_child=true_child,
    )


def fit_depth_two_exact_gini(
    rows: Sequence[FeatureVector],
    targets: Mapping[str, str],
) -> DepthTwoExactGiniTree:
    """Fit the one frozen V2 construct-kill learner on a train-only fold."""

    validated_rows = tuple(
        _strict_revalidate(row, FeatureVector, label="tree training row") for row in rows
    )
    ordered_rows = tuple(sorted(validated_rows, key=lambda item: item.incident_id.encode("utf-8")))
    identifiers = tuple(row.incident_id for row in ordered_rows)
    if not identifiers:
        raise ShortcutTreeError("tree fit requires at least one training incident")
    if len(identifiers) != len(set(identifiers)):
        raise ShortcutTreeError("tree training incidents must be unique")
    if set(targets) != set(identifiers):
        raise ShortcutTreeError("training targets do not exactly cover the train incidents")
    definitions = _feature_definitions(ordered_rows)
    examples = tuple(
        _TrainingExample(row, _validate_prediction_key(targets[row.incident_id]))
        for row in ordered_rows
    )
    root = _fit_element(examples, definitions, 0)
    if not isinstance(root, (TreeLeaf, TreeRootNode)):
        raise ShortcutTreeError("tree fit produced a non-root element")
    return DepthTwoExactGiniTree(
        schema_version="inbar.iter001.depth-two-exact-gini-tree.v1",
        algorithm="depth_two_exact_gini_tree",
        maximum_depth=MAXIMUM_DEPTH,
        minimum_child_incidents=MINIMUM_CHILD_INCIDENTS,
        feature_definitions=definitions,
        feature_root_sha256=_feature_definition_root(definitions),
        train_incident_ids=identifiers,
        train_incident_ids_sha256=_incident_root(identifiers),
        root=root,
    )


def validate_fitted_tree(
    supplied: DepthTwoExactGiniTree,
    rows: Sequence[FeatureVector],
    targets: Mapping[str, str],
) -> None:
    """Reject any supplied fitted state that differs from exact recomputation."""

    validated = _strict_revalidate(supplied, DepthTwoExactGiniTree, label="supplied tree")
    recomputed = fit_depth_two_exact_gini(rows, targets)
    if canonical_json(validated.model_dump(mode="json")) != canonical_json(
        recomputed.model_dump(mode="json")
    ):
        raise ShortcutTreeValidationError("supplied tree differs from exact recomputation")


def validate_tree_prediction(
    supplied: TreePrediction,
    tree: DepthTwoExactGiniTree,
    row: FeatureVector,
    local_hypothesis_by_key: Mapping[str, str],
) -> None:
    """Reject any supplied prediction or trace that differs from exact recomputation."""

    validated = _strict_revalidate(supplied, TreePrediction, label="supplied tree prediction")
    recomputed = predict_depth_two_tree(tree, row, local_hypothesis_by_key)
    if canonical_json(validated.model_dump(mode="json")) != canonical_json(
        recomputed.model_dump(mode="json")
    ):
        raise ShortcutTreeValidationError("supplied prediction differs from exact recomputation")


def _validate_row_against_tree(
    tree: DepthTwoExactGiniTree,
    row: FeatureVector,
) -> dict[str, FeatureValue]:
    observed = tuple((entry.feature_key, feature_value_type(entry.value)) for entry in row.entries)
    expected = tuple((item.feature_key, item.feature_type) for item in tree.feature_definitions)
    if observed != expected:
        raise ShortcutTreeError("prediction row differs from the fitted typed feature union")
    return _feature_map(row)


def predict_depth_two_tree(
    tree: DepthTwoExactGiniTree,
    row: FeatureVector,
    local_hypothesis_by_key: Mapping[str, str],
) -> TreePrediction:
    """Predict one held-out case and perform the required local-key availability check."""

    validated_tree = _strict_revalidate(tree, DepthTwoExactGiniTree, label="prediction tree")
    validated_row = _strict_revalidate(row, FeatureVector, label="prediction row")
    features = _validate_row_against_tree(validated_tree, validated_row)
    local_mapping: dict[str, str] = {}
    for raw_key, raw_hypothesis_id in local_hypothesis_by_key.items():
        key = _validate_prediction_key(raw_key)
        if not isinstance(raw_hypothesis_id, str) or not raw_hypothesis_id:
            raise ShortcutTreeError("local hypothesis ID must be a nonempty string")
        local_mapping[key] = raw_hypothesis_id
    if len(local_mapping.values()) != len(set(local_mapping.values())):
        raise ShortcutTreeError("local hypothesis mapping is not one-to-one")

    element: TreeElement = validated_tree.root
    trace: list[TreePredicate] = []
    while isinstance(element, (DepthOneTreeNode, TreeRootNode)):
        predicate = element.predicate
        trace.append(predicate)
        element = (
            element.true_child
            if _predicate_matches(predicate, features[predicate.feature_key])
            else element.false_child
        )
    proposed = element.prediction_key
    if proposed is None:
        selected = None
        hypothesis_id = None
        reason: Literal["class_tie", "key_unavailable"] | None = "class_tie"
    elif proposed not in local_mapping:
        selected = None
        hypothesis_id = None
        reason = "key_unavailable"
    else:
        selected = proposed
        hypothesis_id = local_mapping[proposed]
        reason = None
    return TreePrediction(
        schema_version="inbar.iter001.tree-prediction.v1",
        incident_id=validated_row.incident_id,
        proposed_prediction_key=proposed,
        selected_prediction_key=selected,
        selected_hypothesis_id=hypothesis_id,
        abstention_reason=reason,
        predicates_evaluated=tuple(trace),
        feature_keys_read=tuple(predicate.feature_key for predicate in trace),
        leaf_depth=element.depth,
    )
