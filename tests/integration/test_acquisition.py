from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from fieldtrue.acquisition import (
    AcquisitionAuditError,
    audit_acquisition,
    load_acquisition_contract,
    render_admission_result,
    verify_preregistration_binding,
    write_admission_output,
)
from fieldtrue.canonical import read_json, sha256_file
from fieldtrue.cli import main
from fieldtrue.control_authority import ControlAuthorityError
from tests.acquisition_helpers import build_acquisition_tree

REPO_ROOT = Path(__file__).parents[2]
CONTRACT_PATH = REPO_ROOT / "protocol" / "acquisition" / "iter001_contract.json"


def test_bootstrap_contract_is_bound_but_cannot_claim_sealed_authority() -> None:
    contract = load_acquisition_contract(CONTRACT_PATH)
    with pytest.raises(AcquisitionAuditError, match="control authority is not sealed"):
        verify_preregistration_binding(REPO_ROOT, contract)
    assert contract.control_authority_status == "bootstrap"
    assert contract.preregistration_commit == "52d71e16a75df12adf47e943fd5c329f6e04d5c0"
    assert sha256_file(REPO_ROOT / contract.preregistration_path) == contract.preregistration_sha256


def test_direct_synthetic_audit_writes_one_atomic_pass_bundle(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    contract = build_acquisition_tree(input_root)
    output_root = tmp_path / "proof"

    report = audit_acquisition(contract, input_root)
    write_admission_output(output_root, report)

    assert report.verdict == "PASS_PILOT"
    assert sorted(path.name for path in output_root.iterdir()) == [
        "RESULT.md",
        "admission_report.json",
        "manifest.json",
    ]
    report = read_json(output_root / "admission_report.json")
    manifest = read_json(output_root / "manifest.json")
    assert report["verdict"] == "PASS_PILOT"
    assert manifest["report_sha256"] == sha256_file(output_root / "admission_report.json")
    assert "not evidence of model performance" in (output_root / "RESULT.md").read_text()


def test_direct_blocked_audit_preserves_full_result(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    contract = build_acquisition_tree(input_root, count=29)
    output_root = tmp_path / "proof"

    report = audit_acquisition(contract, input_root)
    write_admission_output(output_root, report)

    assert report.verdict == "BLOCKED_ACQUISITION"
    assert read_json(output_root / "admission_report.json")["verdict"] == "BLOCKED_ACQUISITION"


def test_canonical_authority_rejects_synthetic_test_root(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    synthetic_contract = build_acquisition_tree(input_root)
    canonical_contract = load_acquisition_contract(CONTRACT_PATH)

    assert synthetic_contract.trust_anchor_public_key != canonical_contract.trust_anchor_public_key
    with pytest.raises(
        AcquisitionAuditError,
        match="acquisition trust or control authority is invalid",
    ) as error:
        audit_acquisition(canonical_contract, input_root)

    assert isinstance(error.value.__cause__, AcquisitionAuditError)
    assert str(error.value.__cause__) == "trust registry is not signed by the contract anchor"


def test_production_cli_fails_closed_for_synthetic_test_root(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_root = tmp_path / "input"
    build_acquisition_tree(input_root)
    output_root = tmp_path / "proof"

    # Repository binding has its own integration test; isolate the evidence-authority boundary.
    monkeypatch.setattr("fieldtrue.cli.verify_preregistration_binding", lambda *_: None)
    monkeypatch.setattr(
        "fieldtrue.cli.verify_admission_control_bundle",
        lambda *_: SimpleNamespace(execution_commit="1" * 40),
    )
    with pytest.raises(SystemExit) as error:
        main(
            [
                "--repo",
                str(REPO_ROOT),
                "acquisition",
                "audit",
                "--contract",
                str(CONTRACT_PATH),
                "--input-root",
                str(input_root),
                "--output-root",
                str(output_root),
            ]
        )

    captured = capsys.readouterr()
    assert error.value.code == 3
    assert captured.out == ""
    assert captured.err.strip() == "acquisition trust or control authority is invalid"
    assert not output_root.exists()


def test_cli_reports_control_authority_failure_without_a_traceback(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_root = tmp_path / "input"
    input_root.mkdir()
    output_root = tmp_path / "proof"

    monkeypatch.setattr("fieldtrue.cli.verify_preregistration_binding", lambda *_: None)

    def reject_control_bundle(*_args: object) -> None:
        raise ControlAuthorityError("control bundle is invalid")

    monkeypatch.setattr("fieldtrue.cli.verify_admission_control_bundle", reject_control_bundle)
    with pytest.raises(SystemExit) as error:
        main(
            [
                "--repo",
                str(REPO_ROOT),
                "acquisition",
                "audit",
                "--contract",
                str(CONTRACT_PATH),
                "--input-root",
                str(input_root),
                "--output-root",
                str(output_root),
            ]
        )

    captured = capsys.readouterr()
    assert error.value.code == 3
    assert captured.out == ""
    assert captured.err.strip() == "control bundle is invalid"
    assert not output_root.exists()


def test_output_root_is_single_use_and_cannot_be_nested_in_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_root = tmp_path / "input"
    contract = build_acquisition_tree(input_root)
    report = audit_acquisition(contract, input_root)
    output_root = tmp_path / "proof"
    write_admission_output(output_root, report)
    with pytest.raises(AcquisitionAuditError, match="must not already exist"):
        write_admission_output(output_root, report)

    monkeypatch.setattr("fieldtrue.cli.verify_preregistration_binding", lambda *_: None)
    monkeypatch.setattr(
        "fieldtrue.cli.verify_admission_control_bundle",
        lambda *_: SimpleNamespace(execution_commit="1" * 40),
    )
    with pytest.raises(SystemExit, match="3") as error:
        main(
            [
                "--repo",
                str(REPO_ROOT),
                "acquisition",
                "audit",
                "--contract",
                str(CONTRACT_PATH),
                "--input-root",
                str(input_root),
                "--output-root",
                str(input_root / "nested-proof"),
            ]
        )
    assert error.value.code == 3


def test_production_cli_rejects_source_change_during_audit(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_root = tmp_path / "input"
    fixture_contract = build_acquisition_tree(input_root)
    fixture_report = audit_acquisition(fixture_contract, input_root)
    output_root = tmp_path / "proof"
    source_bindings = iter(("preflight", "audit-start", "audit-finish"))

    monkeypatch.setattr(
        "fieldtrue.cli.verify_preregistration_binding",
        lambda *_: next(source_bindings),
    )
    monkeypatch.setattr(
        "fieldtrue.cli.verify_admission_control_bundle",
        lambda *_: SimpleNamespace(execution_commit="1" * 40),
    )
    monkeypatch.setattr("fieldtrue.cli.audit_acquisition", lambda *_: fixture_report)

    with pytest.raises(SystemExit) as error:
        main(
            [
                "--repo",
                str(REPO_ROOT),
                "acquisition",
                "audit",
                "--contract",
                str(CONTRACT_PATH),
                "--input-root",
                str(input_root),
                "--output-root",
                str(output_root),
            ]
        )

    captured = capsys.readouterr()
    assert error.value.code == 3
    assert captured.out == ""
    assert captured.err.strip() == "acquisition source closure changed during audit"
    assert not output_root.exists()


def test_noncanonical_selection_and_contract_failures_are_explicit(tmp_path: Path) -> None:
    contract = load_acquisition_contract(CONTRACT_PATH)
    broken = contract.model_copy(update={"preregistration_sha256": "0" * 64})
    with pytest.raises(AcquisitionAuditError, match="not the canonical contract"):
        verify_preregistration_binding(REPO_ROOT, broken)
    with pytest.raises(AcquisitionAuditError, match="invalid acquisition contract"):
        load_acquisition_contract(tmp_path / "missing.json")


def test_result_rendering_is_ascii_and_derived(tmp_path: Path) -> None:
    contract = build_acquisition_tree(tmp_path, count=29)
    report = audit_acquisition(contract, tmp_path)
    rendered = render_admission_result(report)
    assert rendered.decode("ascii").startswith("# Iteration 001")
    assert b"BLOCKED_ACQUISITION" in rendered
