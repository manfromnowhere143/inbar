"""Adversarial controls for the retrospective susceptibility reconstruction.

These tests reproduce the historical prose counts. They do not manufacture a contemporaneous
execution artifact, repair Amendment 006's source binding, or turn the simulator observation into
physical evidence.
"""

from __future__ import annotations

import ast
import json
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

import fieldtrue.masking as masking_module
from fieldtrue.canonical import canonical_json_pretty, sha256_bytes
from fieldtrue.git_trust import TRUSTED_GIT_PATH
from fieldtrue.susceptibility_replay import (
    FREEZE_COMMIT,
    FREEZE_PATH,
    FREEZE_SHA256,
    FREEZE_TREE,
    FROZEN_BASELINES,
    FROZEN_CANDIDATE_KEYS,
    FROZEN_SEEDS,
    FROZEN_SEVERITIES,
    HISTORICAL_SOURCE_SHA256,
    REPORTED_RESULT_COMMIT,
    REPORTED_RESULT_PATH,
    REPORTED_RESULT_SHA256,
    ExactRate,
    SusceptibilityReplayError,
    build_reconstruction,
    load_and_verify_reconstruction,
    reconstruct_predictions,
    reconstruction_bytes,
    write_reconstruction,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
FIRST_A006_IMPLEMENTATION_COMMIT = "a3f1dc0d7e0ab24696a458893e4c836ad489867c"
A006_BOUND_SOURCE_SHA256 = {
    "src/fieldtrue/graded_laboratory.py": (
        "647472e94cac54dd4a295b3bb2452dc90dbbea42587ba5ac093cd1610cbddfb9"
    ),
    "src/fieldtrue/active_selection.py": (
        "a58b445f3ef6c532c2500c1f3ac2828fa406e914b126913593212a8a2f00c044"
    ),
}
FIRST_A006_COMMITTED_SOURCE_SHA256 = {
    "src/fieldtrue/graded_laboratory.py": (
        "b90850fc09d31f32d5c17ea5ef715c4f3a76f3e4e30fb1649c4f24554b031201"
    ),
    "src/fieldtrue/active_selection.py": (
        "cf6846d81c1d3469cebcec5fbe1f408da5708aa3671fe1a7d187946dae4e5044"
    ),
}
ARTIFACT = (
    REPO_ROOT
    / "experiments"
    / "iter001_physical_causal_evidence_acquisition"
    / "proof"
    / "susceptibility_confirmatory_v1"
    / "reconstruction.json"
)


def _historical_bytes(relative: str) -> bytes:
    return subprocess.run(  # noqa: S603 - fixed trusted Git path and fixed commit
        [str(TRUSTED_GIT_PATH), "show", f"{FREEZE_COMMIT}:{relative}"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
    ).stdout


def _git_bytes(commit: str, relative: str) -> bytes:
    return subprocess.run(  # noqa: S603 - fixed trusted Git path and caller-fixed commit
        [str(TRUSTED_GIT_PATH), "show", f"{commit}:{relative}"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
    ).stdout


def _semantic_surface(data: bytes) -> tuple[tuple[str, ...], dict[str, str]]:
    tree = ast.parse(data)
    # Documentation-only corrections are deliberately permitted. Strip docstrings before comparing
    # the executable AST so historical behavior, rather than superseded authority prose, is bound.
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if (
            isinstance(body, list)
            and body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            del body[0]
    imports: list[str] = []
    symbols: dict[str, str] = {}

    def assigned_names(node: ast.AST) -> tuple[str, ...]:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            return (node.name,)
        targets: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            targets.extend(node.targets)
        elif isinstance(node, ast.AnnAssign):
            targets.append(node.target)
        names: list[str] = []
        for target in targets:
            for item in ast.walk(target):
                if isinstance(item, ast.Name):
                    names.append(item.id)
        return tuple(names)

    for node in tree.body:
        rendered = ast.dump(node, include_attributes=False)
        if isinstance(node, ast.Import | ast.ImportFrom):
            imports.append(rendered)
            continue
        for name in assigned_names(node):
            if name in symbols:
                raise AssertionError(f"duplicate top-level symbol: {name}")
            symbols[name] = rendered
    return tuple(imports), symbols


def test_reconstruction_reproduces_every_reported_headline_from_atomic_cells() -> None:
    replay = build_reconstruction()

    assert len(replay.predictions) == 75
    assert len(replay.measurements) == 1125
    assert replay.schedule.baselines == FROZEN_BASELINES
    assert replay.schedule.severities == FROZEN_SEVERITIES
    assert replay.schedule.seeds == FROZEN_SEEDS
    assert replay.laboratory.candidate_keys == FROZEN_CANDIDATE_KEYS

    assert replay.summary.all_cells.cells == 1125
    assert replay.summary.all_cells.agreement == ExactRate(numerator=1121, denominator=1125)
    assert replay.summary.all_cells.masking_events == 64
    assert replay.summary.all_cells.exact_command == ExactRate(numerator=548, denominator=1125)

    assert replay.summary.informative_cells.cells == 750
    assert replay.summary.informative_cells.agreement == ExactRate(numerator=746, denominator=750)
    assert replay.summary.informative_cells.masking_events == 64
    assert replay.summary.informative_cells.exact_command == ExactRate(
        numerator=334, denominator=750
    )

    observed_baselines = {
        row.baseline_command: (
            row.agreement.numerator,
            row.masking_events,
            row.exact_command.numerator,
            row.verdict,
        )
        for row in replay.summary.per_baseline
    }
    assert observed_baselines == {
        30: (371, 49, 151, "informative"),
        45: (375, 15, 183, "informative"),
        60: (375, 0, 214, "vacuous"),
    }


def test_reconstruction_exposes_the_weak_frozen_threshold_and_stronger_diagnostics() -> None:
    summary = build_reconstruction().summary

    assert summary.all_negative_comparator == ExactRate(numerator=686, denominator=750)
    assert summary.all_negative_comparator.numerator * 10 > (
        9 * summary.all_negative_comparator.denominator
    )
    assert summary.confusion.model_dump() == {
        "true_positive": 60,
        "false_positive": 0,
        "false_negative": 4,
        "true_negative": 686,
    }
    assert summary.sensitivity == ExactRate(numerator=60, denominator=64)
    assert summary.specificity == ExactRate(numerator=686, denominator=686)
    assert summary.balanced_accuracy == ExactRate(numerator=31, denominator=32)


def test_prediction_path_cannot_read_the_noisy_plant(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden_graded_run(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("prediction attempted to read the noisy plant")

    monkeypatch.setattr(masking_module, "graded_run", forbidden_graded_run)
    predictions = reconstruct_predictions()

    assert len(predictions) == 75
    assert (
        len({(row.baseline_command, row.mechanism_key, row.severity) for row in predictions}) == 75
    )


def test_the_four_disagreements_are_retained_exactly() -> None:
    disagreements = build_reconstruction().summary.disagreements

    assert [
        (
            row.mechanism_key,
            row.severity,
            row.baseline_command,
            row.seed,
            row.predicted_command,
            row.measured_command,
            row.predicted_masking,
            row.measured_masking,
        )
        for row in disagreements
    ] == [
        ("unknown", 55, 30, 14, 30, 33, False, True),
        ("unknown", 55, 30, 16, 30, 33, False, True),
        ("unknown", 55, 30, 17, 30, 34, False, True),
        ("unknown", 55, 30, 19, 30, 36, False, True),
    ]


def test_historical_source_bindings_resolve_to_the_freeze_commit_bytes() -> None:
    for relative, expected in HISTORICAL_SOURCE_SHA256.items():
        assert sha256_bytes(_historical_bytes(relative)) == expected


def test_replay_bindings_resolve_exact_commits_paths_trees_hashes_and_ancestry() -> None:
    freeze_tree = subprocess.run(  # noqa: S603 - fixed trusted Git path and commit
        [str(TRUSTED_GIT_PATH), "rev-parse", f"{FREEZE_COMMIT}^{{tree}}"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert freeze_tree == FREEZE_TREE
    assert sha256_bytes(_git_bytes(FREEZE_COMMIT, FREEZE_PATH)) == FREEZE_SHA256
    assert (
        sha256_bytes(_git_bytes(REPORTED_RESULT_COMMIT, REPORTED_RESULT_PATH))
        == REPORTED_RESULT_SHA256
    )
    ancestry = subprocess.run(  # noqa: S603 - fixed trusted Git path and commits
        [
            str(TRUSTED_GIT_PATH),
            "merge-base",
            "--is-ancestor",
            FREEZE_COMMIT,
            REPORTED_RESULT_COMMIT,
        ],
        cwd=REPO_ROOT,
        check=False,
    )
    assert ancestry.returncode == 0


def test_current_execution_surface_matches_the_historical_source() -> None:
    exact_paths = set(HISTORICAL_SOURCE_SHA256) - {
        "src/fieldtrue/graded_laboratory.py",
        "src/fieldtrue/masking.py",
    }
    for relative in exact_paths:
        assert (
            sha256_bytes((REPO_ROOT / relative).read_bytes()) == HISTORICAL_SOURCE_SHA256[relative]
        )

    for relative, permitted_additions in {
        "src/fieldtrue/graded_laboratory.py": set(),
        "src/fieldtrue/masking.py": {
            "BANG_BANG_THRESHOLD",
            "COMPENSATOR_FAMILIES",
            "bang_bang_action",
            "half_gain_action",
            "integrating_action",
        },
    }.items():
        historical_imports, historical_symbols = _semantic_surface(_historical_bytes(relative))
        current_imports, current_symbols = _semantic_surface((REPO_ROOT / relative).read_bytes())
        assert current_imports == historical_imports
        assert set(current_symbols) - set(historical_symbols) == permitted_additions
        assert set(historical_symbols) <= set(current_symbols)
        for name, historical_ast in historical_symbols.items():
            assert current_symbols[name] == historical_ast, (relative, name)


def test_a006_bound_hashes_never_entered_reachable_history() -> None:
    amendment = (
        REPO_ROOT
        / "experiments"
        / "iter001_physical_causal_evidence_acquisition"
        / "AMENDMENT_006.md"
    ).read_text(encoding="utf-8")

    for relative, approved in A006_BOUND_SOURCE_SHA256.items():
        commits = subprocess.run(  # noqa: S603 - fixed trusted Git path and current history
            [str(TRUSTED_GIT_PATH), "rev-list", "--reverse", "HEAD", "--", relative],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        assert commits
        assert commits[0] == FIRST_A006_IMPLEMENTATION_COMMIT
        historical_digests = {sha256_bytes(_git_bytes(commit, relative)) for commit in commits}
        first = sha256_bytes(_git_bytes(FIRST_A006_IMPLEMENTATION_COMMIT, relative))
        current = sha256_bytes((REPO_ROOT / relative).read_bytes())
        assert approved in amendment
        assert first == FIRST_A006_COMMITTED_SOURCE_SHA256[relative]
        assert approved not in historical_digests
        assert current != approved

    assert (
        "| `tests/unit/test_graded_laboratory.py` | 20 adversarial controls, all passing |"
        in amendment
    )
    assert (
        "| `tests/unit/test_active_selection.py` | 28 adversarial controls, all passing |"
        in amendment
    )


def test_committed_artifact_is_canonical_and_equals_fresh_recomputation() -> None:
    assert ARTIFACT.is_file()
    assert ARTIFACT.read_bytes() == reconstruction_bytes()

    observed = load_and_verify_reconstruction(ARTIFACT)
    assert observed.status == "retrospective_reconstruction"
    assert observed.authority_effect == "none"
    assert observed.historical_execution_artifact_retained is False


def test_one_mutated_atomic_measurement_is_rejected(tmp_path: Path) -> None:
    document = json.loads(ARTIFACT.read_bytes())
    document["measurements"][0]["commanded_correction"] += 1
    mutated = tmp_path / "mutated.json"
    mutated.write_bytes(canonical_json_pretty(document))

    with pytest.raises(SusceptibilityReplayError, match="differs"):
        load_and_verify_reconstruction(mutated)


@pytest.mark.parametrize("mutation", ["delete", "duplicate"])
def test_incomplete_or_duplicate_schedule_is_rejected(tmp_path: Path, mutation: str) -> None:
    document = json.loads(ARTIFACT.read_bytes())
    if mutation == "delete":
        document["measurements"].pop()
    else:
        document["measurements"].append(document["measurements"][0])
    mutated = tmp_path / f"{mutation}.json"
    mutated.write_bytes(canonical_json_pretty(document))

    with pytest.raises(SusceptibilityReplayError, match="differs"):
        load_and_verify_reconstruction(mutated)


def test_noncanonical_or_invalid_artifact_is_rejected(tmp_path: Path) -> None:
    noncanonical = tmp_path / "noncanonical.json"
    document = json.loads(ARTIFACT.read_bytes())
    noncanonical.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(SusceptibilityReplayError, match="not canonical"):
        load_and_verify_reconstruction(noncanonical)

    invalid = tmp_path / "invalid.json"
    document["summary"]["informative_cells"]["agreement"]["numerator"] = -1
    invalid.write_bytes(canonical_json_pretty(document))
    with pytest.raises(SusceptibilityReplayError, match="cannot load"):
        load_and_verify_reconstruction(invalid)


def test_exact_rate_rejects_an_impossible_fraction() -> None:
    with pytest.raises(ValidationError, match="cannot exceed"):
        ExactRate(numerator=2, denominator=1)


def test_writer_uses_the_same_canonical_bytes(tmp_path: Path) -> None:
    written = tmp_path / "reconstruction.json"
    write_reconstruction(written)
    assert written.read_bytes() == reconstruction_bytes()
