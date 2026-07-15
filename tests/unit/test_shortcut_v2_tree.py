from __future__ import annotations

import json
from fractions import Fraction
from typing import cast

import pytest
from pydantic import TypeAdapter, ValidationError

from fieldtrue.canonical import canonical_json, sha256_value
from fieldtrue.shortcut_v2_hashing import incident_id_list_sha256
from fieldtrue.shortcut_v2_tree import (
    MAXIMUM_DEPTH,
    BooleanFeatureValue,
    CategoricalFeatureValue,
    DepthOneTreeNode,
    DepthTwoExactGiniTree,
    EqualsBooleanPredicate,
    EqualsCategoricalPredicate,
    ExactRational,
    FeatureDefinition,
    FeatureEntry,
    FeatureVector,
    IsMissingPredicate,
    LessThanOrEqualNumericPredicate,
    MissingFeatureValue,
    NumericFeatureValue,
    ShortcutTreeCapacityError,
    ShortcutTreeError,
    ShortcutTreeValidationError,
    TreeLeaf,
    TreePredicate,
    TreePrediction,
    TreeRootNode,
    canonical_decimal,
    enumerate_predicates,
    exact_gini,
    exact_midpoint,
    fit_depth_two_exact_gini,
    parse_canonical_decimal,
    predicate_bytes,
    predict_depth_two_tree,
    validate_fitted_tree,
    validate_tree_prediction,
    weighted_gini,
)

KEY_ZERO = "0" * 64
KEY_ONE = "1" * 64
FEATURE_A = "a" * 64
FEATURE_B = "b" * 64
FEATURE_C = "c" * 64
PREDICATE_SCHEMA = "inbar.iter001.tree-predicate.v1"


def _boolean_row(incident_id: str, a: bool, b: bool = False) -> FeatureVector:
    return FeatureVector(
        incident_id=incident_id,
        entries=(
            FeatureEntry(
                feature_key=FEATURE_A,
                value=BooleanFeatureValue(kind="boolean", value=a),
            ),
            FeatureEntry(
                feature_key=FEATURE_B,
                value=BooleanFeatureValue(kind="boolean", value=b),
            ),
        ),
    )


def _categorical_row(
    incident_id: str,
    value: str | None,
    *,
    feature_key: str = FEATURE_A,
) -> FeatureVector:
    feature_value = (
        MissingFeatureValue(kind="missing", feature_type="categorical")
        if value is None
        else CategoricalFeatureValue(kind="categorical", value=value)
    )
    return FeatureVector(
        incident_id=incident_id,
        entries=(FeatureEntry(feature_key=feature_key, value=feature_value),),
    )


def _golden_training_case() -> tuple[list[FeatureVector], dict[str, str]]:
    cases = (
        (False, False, KEY_ZERO),
        (False, False, KEY_ZERO),
        (False, True, KEY_ZERO),
        (False, True, KEY_ONE),
        (True, False, KEY_ONE),
        (True, False, KEY_ONE),
        (True, True, KEY_ONE),
        (True, True, KEY_ZERO),
    )
    rows: list[FeatureVector] = []
    targets: dict[str, str] = {}
    for index, (a_value, b_value, target) in enumerate(cases):
        incident_id = f"i{index:02d}"
        rows.append(_boolean_row(incident_id, a_value, b_value))
        targets[incident_id] = target
    return rows, targets


def test_canonical_decimal_and_midpoint_are_context_free() -> None:
    huge_left = "999999999999999999999999999999.9"
    huge_right = "1000000000000000000000000000000.1"
    assert exact_midpoint("0.1", "0.2") == "0.15"
    assert exact_midpoint("-0.2", "0.1") == "-0.05"
    assert exact_midpoint(huge_left, huge_right) == "1000000000000000000000000000000"
    assert parse_canonical_decimal("-123.456") == Fraction(-15432, 125)
    assert canonical_decimal(Fraction(1, 40)) == "0.025"
    assert canonical_decimal(Fraction(0)) == "0"

    for invalid in ("-0", "0.0", "1.20", "+1", "01", "1e3", "NaN", "Infinity"):
        with pytest.raises(ShortcutTreeError):
            parse_canonical_decimal(invalid)
    with pytest.raises(ShortcutTreeError, match="strictly ordered"):
        exact_midpoint("1", "1")
    with pytest.raises(ShortcutTreeError, match="finite decimal"):
        canonical_decimal(Fraction(1, 3))
    with pytest.raises(ShortcutTreeError, match="must be a string"):
        parse_canonical_decimal(cast(str, 1))


def test_decimal_arithmetic_exceeds_python_integer_string_guard_without_global_mutation() -> None:
    huge = "1" * 5_000
    assert canonical_decimal(parse_canonical_decimal(huge)) == huge

    huge_left = "1" + "0" * 4_999
    huge_right = "2" + "0" * 4_999
    assert exact_midpoint(huge_left, huge_right) == "15" + "0" * 4_998


@pytest.mark.parametrize("incident_id", [cast(str, 1), "\ud800"])
def test_incident_list_hash_rejects_nonstring_and_non_utf8_values(incident_id: str) -> None:
    with pytest.raises(ValueError, match="valid UTF-8 strings"):
        incident_id_list_sha256((incident_id,))


def test_categorical_values_require_real_utf8_and_feature_vectors_are_canonical() -> None:
    with pytest.raises(ValidationError, match="canonical UTF-8"):
        CategoricalFeatureValue(kind="categorical", value="\ud800")
    with pytest.raises(ValidationError, match="canonical UTF-8"):
        EqualsCategoricalPredicate(
            schema_version=PREDICATE_SCHEMA,
            feature_key=FEATURE_A,
            operator="equals_categorical",
            operand="\udfff",
        )

    entry_a = FeatureEntry(
        feature_key=FEATURE_A,
        value=BooleanFeatureValue(kind="boolean", value=False),
    )
    entry_b = FeatureEntry(
        feature_key=FEATURE_B,
        value=BooleanFeatureValue(kind="boolean", value=True),
    )
    with pytest.raises(ValidationError, match="sorted"):
        FeatureVector(incident_id="unordered", entries=(entry_b, entry_a))
    with pytest.raises(ValidationError, match="duplicate"):
        FeatureVector(incident_id="duplicate", entries=(entry_a, entry_a))


def test_predicate_union_has_exact_fields_and_operand_types() -> None:
    adapter: TypeAdapter[TreePredicate] = TypeAdapter(TreePredicate)
    predicate = adapter.validate_python(
        {
            "schema_version": "inbar.iter001.tree-predicate.v1",
            "feature_key": FEATURE_A,
            "operator": "is_missing",
            "operand": None,
        },
        strict=True,
    )
    assert isinstance(predicate, IsMissingPredicate)

    invalid_payloads = (
        {
            "schema_version": "inbar.iter001.tree-predicate.v1",
            "feature_key": FEATURE_A,
            "operator": "is_missing",
            "operand": False,
        },
        {
            "schema_version": "inbar.iter001.tree-predicate.v1",
            "feature_key": FEATURE_A,
            "operator": "equals_boolean",
            "operand": "false",
        },
        {
            "schema_version": "inbar.iter001.tree-predicate.v1",
            "feature_key": FEATURE_A,
            "operator": "equals_categorical",
            "operand": "x",
            "extra": "forbidden",
        },
        {
            "schema_version": "inbar.iter001.tree-predicate.v1",
            "feature_key": FEATURE_A,
            "operator": "less_than_or_equal_numeric",
            "operand": "1.0",
        },
    )
    for payload in invalid_payloads:
        with pytest.raises(ValidationError):
            adapter.validate_python(payload, strict=True)


def test_exact_gini_arithmetic_uses_reduced_fractions() -> None:
    assert exact_gini({KEY_ZERO: 3, KEY_ONE: 1}) == Fraction(3, 8)
    assert weighted_gini({KEY_ZERO: 2}, {KEY_ZERO: 1, KEY_ONE: 1}) == Fraction(1, 4)
    with pytest.raises(ShortcutTreeError):
        exact_gini({})
    with pytest.raises(ShortcutTreeError):
        exact_gini({KEY_ZERO: 0})
    with pytest.raises(ShortcutTreeError, match="nonempty"):
        weighted_gini({}, {KEY_ZERO: 1})
    with pytest.raises(ValidationError, match="reduced"):
        ExactRational(numerator=2, denominator=4)
    with pytest.raises(ShortcutTreeError, match="negative"):
        ExactRational.from_fraction(Fraction(-1, 2))


def test_golden_depth_two_tree_and_permutation_invariance() -> None:
    rows, targets = _golden_training_case()
    tree = fit_depth_two_exact_gini(rows, targets)

    assert sha256_value(tree.model_dump(mode="json")) == (
        "d74313c5762ed5a4166eacbebaecf0917fa4d8da31b63a8c5e79fdd4bfe71407"
    )
    assert isinstance(tree.root, TreeRootNode)
    assert tree.root.predicate == EqualsBooleanPredicate(
        schema_version=PREDICATE_SCHEMA,
        feature_key=FEATURE_A,
        operator="equals_boolean",
        operand=False,
    )
    assert tree.root.impurity.as_fraction() == Fraction(1, 2)
    assert tree.root.split_impurity.as_fraction() == Fraction(3, 8)
    assert isinstance(tree.root.false_child, DepthOneTreeNode)
    assert isinstance(tree.root.true_child, DepthOneTreeNode)
    assert tree.root.false_child.predicate == EqualsBooleanPredicate(
        schema_version=PREDICATE_SCHEMA,
        feature_key=FEATURE_B,
        operator="equals_boolean",
        operand=False,
    )
    assert tree.root.true_child.predicate == EqualsBooleanPredicate(
        schema_version=PREDICATE_SCHEMA,
        feature_key=FEATURE_B,
        operator="equals_boolean",
        operand=False,
    )
    assert max(element.depth for element in _elements(tree)) == MAXIMUM_DEPTH
    assert any(
        isinstance(element, TreeLeaf) and element.impurity.as_fraction() > 0
        for element in _elements(tree)
    )

    permuted = fit_depth_two_exact_gini(
        list(reversed(rows)),
        dict(reversed(tuple(targets.items()))),
    )
    assert canonical_json(permuted.model_dump(mode="json")) == canonical_json(
        tree.model_dump(mode="json")
    )
    validate_fitted_tree(tree, list(reversed(rows)), targets)


def _elements(
    tree: DepthTwoExactGiniTree,
) -> tuple[TreeLeaf | DepthOneTreeNode | TreeRootNode, ...]:
    root = tree.root
    elements: list[TreeLeaf | DepthOneTreeNode | TreeRootNode] = [root]
    if isinstance(root, TreeRootNode):
        for child in (root.false_child, root.true_child):
            elements.append(child)
            if isinstance(child, DepthOneTreeNode):
                elements.extend((child.false_child, child.true_child))
    return tuple(elements)


def test_equal_gini_ties_use_unsigned_canonical_predicate_bytes() -> None:
    false_predicate = EqualsBooleanPredicate(
        schema_version=PREDICATE_SCHEMA,
        feature_key=FEATURE_A,
        operator="equals_boolean",
        operand=False,
    )
    true_predicate = EqualsBooleanPredicate(
        schema_version=PREDICATE_SCHEMA,
        feature_key=FEATURE_A,
        operator="equals_boolean",
        operand=True,
    )
    assert predicate_bytes(false_predicate) < predicate_bytes(true_predicate)

    rows = [
        _boolean_row("t0", False, False),
        _boolean_row("t1", False, False),
        _boolean_row("t2", True, True),
        _boolean_row("t3", True, True),
    ]
    targets = {"t0": KEY_ZERO, "t1": KEY_ZERO, "t2": KEY_ONE, "t3": KEY_ONE}
    tree = fit_depth_two_exact_gini(rows, targets)
    assert isinstance(tree.root, TreeRootNode)
    assert tree.root.predicate.feature_key == FEATURE_A
    assert tree.root.predicate == false_predicate


def test_missing_unseen_and_key_unavailable_prediction_semantics() -> None:
    missing_rows = [
        *(_categorical_row(f"m{index}", None) for index in range(4)),
        _categorical_row("m4", "x"),
        _categorical_row("m5", "x"),
        _categorical_row("m6", "y"),
        _categorical_row("m7", "y"),
    ]
    missing_targets = {
        row.incident_id: KEY_ZERO if index < 4 else KEY_ONE
        for index, row in enumerate(missing_rows)
    }
    missing_tree = fit_depth_two_exact_gini(missing_rows, missing_targets)
    assert isinstance(missing_tree.root, TreeRootNode)
    assert isinstance(missing_tree.root.predicate, IsMissingPredicate)
    missing_prediction = predict_depth_two_tree(
        missing_tree,
        _categorical_row("held-missing", None),
        {KEY_ZERO: "hypothesis-zero", KEY_ONE: "hypothesis-one"},
    )
    assert missing_prediction.selected_prediction_key == KEY_ZERO
    assert missing_prediction.selected_hypothesis_id == "hypothesis-zero"

    rows = [
        *(_categorical_row(f"u{index}", "x") for index in range(4)),
        *(_categorical_row(f"u{index}", "y") for index in range(4, 8)),
    ]
    targets = {
        row.incident_id: KEY_ZERO if index < 4 else KEY_ONE for index, row in enumerate(rows)
    }
    tree = fit_depth_two_exact_gini(rows, targets)
    assert isinstance(tree.root, TreeRootNode)
    assert tree.root.predicate == EqualsCategoricalPredicate(
        schema_version=PREDICATE_SCHEMA,
        feature_key=FEATURE_A,
        operator="equals_categorical",
        operand="x",
    )
    unseen = _categorical_row("held-unseen", "z")
    selected = predict_depth_two_tree(
        tree,
        unseen,
        {KEY_ZERO: "hypothesis-zero", KEY_ONE: "hypothesis-one"},
    )
    assert selected.selected_prediction_key == KEY_ONE
    assert selected.abstention_reason is None

    unavailable = predict_depth_two_tree(tree, unseen, {KEY_ZERO: "hypothesis-zero"})
    assert unavailable.proposed_prediction_key == KEY_ONE
    assert unavailable.selected_prediction_key is None
    assert unavailable.selected_hypothesis_id is None
    assert unavailable.abstention_reason == "key_unavailable"


def test_no_improvement_minimum_child_and_class_tie_make_leaves() -> None:
    no_variation = [_categorical_row(f"n{index}", "same") for index in range(4)]
    modal_tree = fit_depth_two_exact_gini(
        no_variation,
        {"n0": KEY_ZERO, "n1": KEY_ZERO, "n2": KEY_ZERO, "n3": KEY_ONE},
    )
    assert isinstance(modal_tree.root, TreeLeaf)
    assert modal_tree.root.prediction_key == KEY_ZERO

    tied_tree = fit_depth_two_exact_gini(
        no_variation,
        {"n0": KEY_ZERO, "n1": KEY_ZERO, "n2": KEY_ONE, "n3": KEY_ONE},
    )
    assert isinstance(tied_tree.root, TreeLeaf)
    prediction = predict_depth_two_tree(
        tied_tree,
        _categorical_row("held-tie", "same"),
        {KEY_ZERO: "hypothesis-zero", KEY_ONE: "hypothesis-one"},
    )
    assert prediction.proposed_prediction_key is None
    assert prediction.abstention_reason == "class_tie"
    assert prediction.leaf_depth == 0

    imbalanced = [
        _categorical_row("rare", "rare"),
        *(_categorical_row(f"common-{index}", "common") for index in range(5)),
    ]
    imbalanced_targets = {
        row.incident_id: KEY_ONE if row.incident_id == "rare" else KEY_ZERO for row in imbalanced
    }
    minimum_child_tree = fit_depth_two_exact_gini(imbalanced, imbalanced_targets)
    assert isinstance(minimum_child_tree.root, TreeLeaf)
    assert minimum_child_tree.root.prediction_key == KEY_ZERO


def test_numeric_predicates_use_exact_consecutive_midpoints() -> None:
    rows = [
        FeatureVector(
            incident_id=f"numeric-{index}",
            entries=(
                FeatureEntry(
                    feature_key=FEATURE_A,
                    value=NumericFeatureValue(kind="numeric", value=value),
                ),
            ),
        )
        for index, value in enumerate(("0.1", "0.2", "1", "10"))
    ]
    predicates = enumerate_predicates(rows)
    numeric_operands = tuple(
        predicate.operand
        for predicate in predicates
        if isinstance(predicate, LessThanOrEqualNumericPredicate)
    )
    assert numeric_operands == ("0.15", "0.6", "5.5")

    numeric_targets = {
        row.incident_id: KEY_ZERO if index < 2 else KEY_ONE for index, row in enumerate(rows)
    }
    tree = fit_depth_two_exact_gini(rows, numeric_targets)
    assert isinstance(tree.root, TreeRootNode)
    prediction = predict_depth_two_tree(
        tree,
        FeatureVector(
            incident_id="numeric-held",
            entries=(
                FeatureEntry(
                    feature_key=FEATURE_A,
                    value=NumericFeatureValue(kind="numeric", value="0.15"),
                ),
            ),
        ),
        {KEY_ZERO: "numeric-low", KEY_ONE: "numeric-high"},
    )
    assert prediction.selected_hypothesis_id == "numeric-low"


def test_explicit_node_definitions_cannot_bypass_union_or_ordering() -> None:
    row = _categorical_row("node-row", "x")
    valid = FeatureDefinition(feature_key=FEATURE_A, feature_type="categorical")
    absent = FeatureDefinition(feature_key=FEATURE_B, feature_type="categorical")
    wrong_type = FeatureDefinition(feature_key=FEATURE_A, feature_type="numeric")

    with pytest.raises(ShortcutTreeError, match="at least one"):
        enumerate_predicates([], (valid,))
    with pytest.raises(ShortcutTreeError, match="canonically ordered"):
        enumerate_predicates([row], (absent, valid))
    with pytest.raises(ShortcutTreeError, match="duplicate"):
        enumerate_predicates([row], (valid, valid))
    with pytest.raises(ShortcutTreeError, match="exactly match"):
        enumerate_predicates([row], (valid, absent))
    with pytest.raises(ShortcutTreeError, match="exactly match"):
        enumerate_predicates([row], (wrong_type,))
    with pytest.raises(ShortcutTreeError, match="exactly match"):
        enumerate_predicates([row], ())

    local = enumerate_predicates(
        [_categorical_row("local-a", "a"), _categorical_row("local-b", "b")],
    )
    operands = {
        predicate.operand
        for predicate in local
        if isinstance(predicate, EqualsCategoricalPredicate)
    }
    assert operands == {"a", "b"}
    assert "outside-node" not in operands


def test_feature_and_predicate_capacity_fail_closed() -> None:
    feature_keys = tuple(f"{index:064x}" for index in range(4_097))
    oversized = FeatureVector(
        incident_id="oversized",
        entries=tuple(
            FeatureEntry(
                feature_key=key,
                value=BooleanFeatureValue(kind="boolean", value=False),
            )
            for key in feature_keys
        ),
    )
    with pytest.raises(ShortcutTreeCapacityError, match="4096"):
        fit_depth_two_exact_gini([oversized], {"oversized": KEY_ZERO})
    empty = FeatureVector(incident_id="empty-first", entries=())
    with pytest.raises(ShortcutTreeCapacityError, match="4096"):
        fit_depth_two_exact_gini(
            [empty, oversized],
            {"empty-first": KEY_ZERO, "oversized": KEY_ONE},
        )
    oversized_definitions = tuple(
        FeatureDefinition(feature_key=key, feature_type="boolean") for key in feature_keys
    )
    with pytest.raises(ShortcutTreeCapacityError, match="4096"):
        enumerate_predicates([empty], oversized_definitions)

    oversized_tree = fit_depth_two_exact_gini([empty], {"empty-first": KEY_ZERO}).model_dump(
        mode="json"
    )
    oversized_tree["feature_definitions"] = [
        definition.model_dump(mode="json") for definition in oversized_definitions
    ]
    oversized_tree["feature_root_sha256"] = sha256_value(oversized_tree["feature_definitions"])
    with pytest.raises(ValidationError, match="feature ceiling"):
        _model_validate_tree(oversized_tree)

    predicate_feature_keys = tuple(f"{index:064x}" for index in range(2_500))
    values = tuple(
        CategoricalFeatureValue(kind="categorical", value=f"value-{index:02d}")
        for index in range(40)
    )
    rows = [
        FeatureVector(
            incident_id=f"capacity-{row_index:02d}",
            entries=tuple(
                FeatureEntry(feature_key=key, value=values[row_index])
                for key in predicate_feature_keys
            ),
        )
        for row_index in range(40)
    ]
    targets = {
        row.incident_id: KEY_ZERO if index < 20 else KEY_ONE for index, row in enumerate(rows)
    }
    with pytest.raises(ShortcutTreeCapacityError, match="100000"):
        fit_depth_two_exact_gini(rows, targets)


def test_depth_overflow_and_tampered_state_are_rejected() -> None:
    rows, targets = _golden_training_case()
    tree = fit_depth_two_exact_gini(rows, targets)
    payload = tree.model_dump(mode="json")
    assert payload["root"]["kind"] == "node"

    impurity_tamper = json.loads(json.dumps(payload))
    impurity_tamper["root"]["split_impurity"] = {"numerator": 0, "denominator": 1}
    with pytest.raises(ValidationError, match="split impurity"):
        DepthTwoExactGiniTree.model_validate_json(json.dumps(impurity_tamper))

    depth_tamper = json.loads(json.dumps(payload))
    depth_two_leaf = depth_tamper["root"]["false_child"]["false_child"]
    depth_two_leaf["kind"] = "node"
    with pytest.raises(ValidationError):
        DepthTwoExactGiniTree.model_validate_json(json.dumps(depth_tamper))

    routing_tamper = json.loads(json.dumps(payload))
    routing_tamper["root"]["predicate"]["operand"] = True
    routing_tamper["root"]["false_child"], routing_tamper["root"]["true_child"] = (
        routing_tamper["root"]["true_child"],
        routing_tamper["root"]["false_child"],
    )
    structurally_valid = DepthTwoExactGiniTree.model_validate_json(json.dumps(routing_tamper))
    with pytest.raises(ShortcutTreeValidationError, match="exact recomputation"):
        validate_fitted_tree(structurally_valid, rows, targets)


def _model_validate_tree(payload: dict[str, object]) -> DepthTwoExactGiniTree:
    return DepthTwoExactGiniTree.model_validate_json(json.dumps(payload))


def test_tree_element_statistics_and_leaf_output_reject_tampering() -> None:
    rows, targets = _golden_training_case()
    payload = fit_depth_two_exact_gini(rows, targets).model_dump(mode="json")

    unordered = json.loads(json.dumps(payload))
    unordered["root"]["train_incident_ids"].reverse()
    with pytest.raises(ValidationError, match="canonically ordered"):
        _model_validate_tree(unordered)

    duplicate_incident = json.loads(json.dumps(payload))
    duplicate_incident["root"]["train_incident_ids"][-1] = duplicate_incident["root"][
        "train_incident_ids"
    ][-2]
    duplicate_incident["root"]["train_incident_ids_sha256"] = sha256_value(
        duplicate_incident["root"]["train_incident_ids"]
    )
    with pytest.raises(ValidationError, match="duplicate incidents"):
        _model_validate_tree(duplicate_incident)

    wrong_incident_root = json.loads(json.dumps(payload))
    wrong_incident_root["root"]["train_incident_ids_sha256"] = "f" * 64
    with pytest.raises(ValidationError, match="incident root"):
        _model_validate_tree(wrong_incident_root)

    unordered_counts = json.loads(json.dumps(payload))
    unordered_counts["root"]["class_counts"].reverse()
    with pytest.raises(ValidationError, match="class counts must be canonically ordered"):
        _model_validate_tree(unordered_counts)

    duplicate_counts = json.loads(json.dumps(payload))
    duplicate_counts["root"]["class_counts"] = [
        {"prediction_key": KEY_ZERO, "count": 4},
        {"prediction_key": KEY_ZERO, "count": 4},
    ]
    with pytest.raises(ValidationError, match="duplicate keys"):
        _model_validate_tree(duplicate_counts)

    incomplete_counts = json.loads(json.dumps(payload))
    incomplete_counts["root"]["class_counts"][0]["count"] = 3
    with pytest.raises(ValidationError, match="do not cover"):
        _model_validate_tree(incomplete_counts)

    wrong_impurity = json.loads(json.dumps(payload))
    wrong_impurity["root"]["impurity"] = {"numerator": 0, "denominator": 1}
    with pytest.raises(ValidationError, match="does not follow"):
        _model_validate_tree(wrong_impurity)

    wrong_leaf = json.loads(json.dumps(payload))
    leaf = wrong_leaf["root"]["false_child"]["true_child"]
    assert leaf["prediction_key"] == KEY_ONE
    leaf["prediction_key"] = KEY_ZERO
    with pytest.raises(ValidationError, match="unique modal"):
        _model_validate_tree(wrong_leaf)


def _simple_split_tree() -> DepthTwoExactGiniTree:
    rows = [
        _boolean_row("simple-0", False),
        _boolean_row("simple-1", False),
        _boolean_row("simple-2", True),
        _boolean_row("simple-3", True),
    ]
    targets = {
        "simple-0": KEY_ZERO,
        "simple-1": KEY_ZERO,
        "simple-2": KEY_ONE,
        "simple-3": KEY_ONE,
    }
    return fit_depth_two_exact_gini(rows, targets)


def test_node_partition_size_aggregation_and_improvement_are_derived() -> None:
    payload = _simple_split_tree().model_dump(mode="json")
    assert payload["root"]["false_child"]["kind"] == "leaf"

    wrong_depth = json.loads(json.dumps(payload))
    wrong_depth["root"]["false_child"]["depth"] = 2
    with pytest.raises(ValidationError, match="wrong depth"):
        _model_validate_tree(wrong_depth)

    undersized = json.loads(json.dumps(payload))
    child = undersized["root"]["false_child"]
    child["train_incident_ids"] = child["train_incident_ids"][:1]
    child["train_incident_ids_sha256"] = incident_id_list_sha256(child["train_incident_ids"])
    child["class_counts"][0]["count"] = 1
    with pytest.raises(ValidationError, match="minimum child size"):
        _model_validate_tree(undersized)

    overlapping = json.loads(json.dumps(payload))
    overlapping["root"]["false_child"] = overlapping["root"]["true_child"]
    with pytest.raises(ValidationError, match="partition"):
        _model_validate_tree(overlapping)

    wrong_aggregate = json.loads(json.dumps(payload))
    false_child = wrong_aggregate["root"]["false_child"]
    replacement_key = KEY_ONE if false_child["prediction_key"] == KEY_ZERO else KEY_ZERO
    false_child["class_counts"] = [{"prediction_key": replacement_key, "count": 2}]
    false_child["prediction_key"] = replacement_key
    with pytest.raises(ValidationError, match="aggregate"):
        _model_validate_tree(wrong_aggregate)

    no_improvement = json.loads(json.dumps(payload))
    no_improvement["root"]["class_counts"] = [{"prediction_key": KEY_ZERO, "count": 4}]
    no_improvement["root"]["impurity"] = {"numerator": 0, "denominator": 1}
    for branch in ("false_child", "true_child"):
        child = no_improvement["root"][branch]
        child["class_counts"] = [{"prediction_key": KEY_ZERO, "count": 2}]
        child["prediction_key"] = KEY_ZERO
    with pytest.raises(ValidationError, match="strictly improve"):
        _model_validate_tree(no_improvement)


def test_tree_level_roots_feature_types_and_train_binding_are_derived() -> None:
    rows, targets = _golden_training_case()
    payload = fit_depth_two_exact_gini(rows, targets).model_dump(mode="json")

    reversed_definitions = json.loads(json.dumps(payload))
    reversed_definitions["feature_definitions"].reverse()
    reversed_definitions["feature_root_sha256"] = sha256_value(
        reversed_definitions["feature_definitions"]
    )
    with pytest.raises(ValidationError, match="feature definitions must be canonically ordered"):
        _model_validate_tree(reversed_definitions)

    duplicate_definitions = json.loads(json.dumps(payload))
    duplicate_definitions["feature_definitions"] = [
        duplicate_definitions["feature_definitions"][0],
        duplicate_definitions["feature_definitions"][0],
    ]
    duplicate_definitions["feature_root_sha256"] = sha256_value(
        duplicate_definitions["feature_definitions"]
    )
    with pytest.raises(ValidationError, match="duplicate keys"):
        _model_validate_tree(duplicate_definitions)

    wrong_feature_root = json.loads(json.dumps(payload))
    wrong_feature_root["feature_root_sha256"] = "f" * 64
    with pytest.raises(ValidationError, match="feature root"):
        _model_validate_tree(wrong_feature_root)

    unordered_train = json.loads(json.dumps(payload))
    unordered_train["train_incident_ids"].reverse()
    with pytest.raises(ValidationError, match="train incidents must be canonically ordered"):
        _model_validate_tree(unordered_train)

    duplicate_train = json.loads(json.dumps(payload))
    duplicate_train["train_incident_ids"][-1] = duplicate_train["train_incident_ids"][-2]
    duplicate_train["train_incident_ids_sha256"] = sha256_value(
        duplicate_train["train_incident_ids"]
    )
    with pytest.raises(ValidationError, match="train incidents contain duplicates"):
        _model_validate_tree(duplicate_train)

    wrong_train_root = json.loads(json.dumps(payload))
    wrong_train_root["train_incident_ids_sha256"] = "f" * 64
    with pytest.raises(ValidationError, match="train incident root"):
        _model_validate_tree(wrong_train_root)

    incomplete_root_binding = json.loads(json.dumps(payload))
    incomplete_root_binding["train_incident_ids"] = incomplete_root_binding["train_incident_ids"][
        :-1
    ]
    incomplete_root_binding["train_incident_ids_sha256"] = incident_id_list_sha256(
        incomplete_root_binding["train_incident_ids"]
    )
    with pytest.raises(ValidationError, match="complete train incident set"):
        _model_validate_tree(incomplete_root_binding)

    absent_feature = json.loads(json.dumps(payload))
    absent_feature["root"]["predicate"]["feature_key"] = FEATURE_C
    with pytest.raises(ValidationError, match="absent feature"):
        _model_validate_tree(absent_feature)

    wrong_operator = json.loads(json.dumps(payload))
    wrong_operator["root"]["predicate"] = {
        "schema_version": "inbar.iter001.tree-predicate.v1",
        "feature_key": FEATURE_A,
        "operator": "equals_categorical",
        "operand": "false",
    }
    with pytest.raises(ValidationError, match="disagrees with feature type"):
        _model_validate_tree(wrong_operator)


def test_supplied_prediction_is_recomputed_and_trace_contract_is_strict() -> None:
    rows, targets = _golden_training_case()
    tree = fit_depth_two_exact_gini(rows, targets)
    heldout = _boolean_row("prediction-held", False, False)
    mapping = {KEY_ZERO: "hypothesis-zero", KEY_ONE: "hypothesis-one"}
    prediction = predict_depth_two_tree(tree, heldout, mapping)
    validate_tree_prediction(prediction, tree, heldout, mapping)

    tampered = prediction.model_copy(update={"selected_hypothesis_id": "hypothesis-alternate"})
    with pytest.raises(ShortcutTreeValidationError, match="exact recomputation"):
        validate_tree_prediction(tampered, tree, heldout, mapping)

    payload = prediction.model_dump(mode="json")
    wrong_depth = json.loads(json.dumps(payload))
    wrong_depth["leaf_depth"] = 0
    with pytest.raises(ValidationError, match="trace length"):
        TreePrediction.model_validate_json(json.dumps(wrong_depth))

    wrong_reads = json.loads(json.dumps(payload))
    wrong_reads["feature_keys_read"][0] = FEATURE_C
    with pytest.raises(ValidationError, match="feature reads"):
        TreePrediction.model_validate_json(json.dumps(wrong_reads))

    wrong_selection = json.loads(json.dumps(payload))
    wrong_selection["selected_prediction_key"] = KEY_ONE
    with pytest.raises(ValidationError, match="selection"):
        TreePrediction.model_validate_json(json.dumps(wrong_selection))

    invalid_class_tie = json.loads(json.dumps(payload))
    invalid_class_tie["abstention_reason"] = "class_tie"
    with pytest.raises(ValidationError, match="selection"):
        TreePrediction.model_validate_json(json.dumps(invalid_class_tie))

    invalid_unavailable = json.loads(json.dumps(payload))
    invalid_unavailable["abstention_reason"] = "key_unavailable"
    with pytest.raises(ValidationError, match="selection"):
        TreePrediction.model_validate_json(json.dumps(invalid_unavailable))


def test_training_and_prediction_inputs_must_cover_one_typed_union() -> None:
    with pytest.raises(ShortcutTreeError, match="at least one"):
        fit_depth_two_exact_gini([], {})

    row = _boolean_row("typed-0", False)
    missing_target = {"other": KEY_ZERO}
    with pytest.raises(ShortcutTreeError, match="exactly cover"):
        fit_depth_two_exact_gini([row], missing_target)

    mismatched = FeatureVector(
        incident_id="typed-1",
        entries=(
            FeatureEntry(
                feature_key=FEATURE_A,
                value=CategoricalFeatureValue(kind="categorical", value="false"),
            ),
            FeatureEntry(
                feature_key=FEATURE_B,
                value=BooleanFeatureValue(kind="boolean", value=False),
            ),
        ),
    )
    with pytest.raises(ShortcutTreeError, match="typed feature union"):
        fit_depth_two_exact_gini(
            [row, mismatched],
            {"typed-0": KEY_ZERO, "typed-1": KEY_ONE},
        )

    with pytest.raises(ShortcutTreeError, match="unique"):
        fit_depth_two_exact_gini(
            [row, row],
            {"typed-0": KEY_ZERO},
        )
    with pytest.raises(ShortcutTreeError, match="canonical shared prediction key"):
        fit_depth_two_exact_gini([row], {"typed-0": "incident-local-target"})

    rows, targets = _golden_training_case()
    tree = fit_depth_two_exact_gini(rows, targets)
    incomplete_heldout = FeatureVector(
        incident_id="held-incomplete",
        entries=(
            FeatureEntry(
                feature_key=FEATURE_A,
                value=BooleanFeatureValue(kind="boolean", value=False),
            ),
        ),
    )
    with pytest.raises(ShortcutTreeError, match="typed feature union"):
        predict_depth_two_tree(tree, incomplete_heldout, {KEY_ZERO: "hypothesis-zero"})

    heldout = _boolean_row("held-mapping", False)
    with pytest.raises(ShortcutTreeError, match="canonical shared prediction key"):
        predict_depth_two_tree(tree, heldout, {"bad-key": "hypothesis-zero"})
    with pytest.raises(ShortcutTreeError, match="nonempty"):
        predict_depth_two_tree(tree, heldout, {KEY_ZERO: ""})
    with pytest.raises(ShortcutTreeError, match="one-to-one"):
        predict_depth_two_tree(
            tree,
            heldout,
            {KEY_ZERO: "same-hypothesis", KEY_ONE: "same-hypothesis"},
        )


def test_persisted_tree_constants_cannot_be_repaired_from_omitted_fields() -> None:
    rows, targets = _golden_training_case()
    payload = fit_depth_two_exact_gini(rows, targets).model_dump(mode="json")
    omission_paths = (
        ("schema_version",),
        ("algorithm",),
        ("maximum_depth",),
        ("minimum_child_incidents",),
        ("root", "kind"),
        ("root", "depth"),
        ("root", "predicate", "schema_version"),
        ("root", "predicate", "operator"),
        ("root", "false_child", "kind"),
        ("root", "false_child", "depth"),
    )
    for path in omission_paths:
        candidate = json.loads(json.dumps(payload))
        parent = candidate
        for part in path[:-1]:
            parent = parent[part]
        parent.pop(path[-1])
        with pytest.raises(ValidationError):
            _model_validate_tree(candidate)

    row_payload = _boolean_row("required-kind", False).model_dump(mode="json")
    row_payload["entries"][0]["value"].pop("kind")
    with pytest.raises(ValidationError):
        FeatureVector.model_validate(row_payload)


def test_prediction_revalidates_copied_tree_and_row_models() -> None:
    rows, targets = _golden_training_case()
    tree = fit_depth_two_exact_gini(rows, targets)
    copied_tree = tree.model_copy(update={"algorithm": "substitute"})
    with pytest.raises(ShortcutTreeValidationError, match="strict revalidation"):
        predict_depth_two_tree(
            copied_tree,
            _boolean_row("held-copy", False),
            {KEY_ZERO: "hypothesis-zero"},
        )

    row = _boolean_row("held-copy", False)
    copied_row = row.model_copy(update={"incident_id": ""})
    with pytest.raises(ShortcutTreeValidationError, match="strict revalidation"):
        predict_depth_two_tree(tree, copied_row, {KEY_ZERO: "hypothesis-zero"})
