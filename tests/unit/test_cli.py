from __future__ import annotations

import json
from pathlib import Path

import pytest
from nacl.signing import SigningKey

import fieldtrue.cli as cli_module
from fieldtrue.canonical import canonical_json_pretty
from fieldtrue.cli import _repo_root, main
from fieldtrue.domain import GateResult, GateStatus, ReadinessReport
from fieldtrue.mission import MissionValidation, ValidationCheck
from fieldtrue.receipts import SignedLedger
from tests.helpers import create_adapt_source, runtime_identity


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "mission").mkdir(parents=True)
    (repo / "mission" / "contract.json").write_text("{}\n")
    (repo / "memory").mkdir()
    (repo / "memory" / "research_engine_extraction.jsonl").write_text("")
    return repo


def _report(verdict: str = "BLOCKED_EVIDENCE") -> ReadinessReport:
    return ReadinessReport(
        dataset_id="fixture",
        gates=(
            GateResult(
                gate_id="fixture-gate",
                status=GateStatus.BLOCKED,
                observed=0,
                requirement="one",
                detail="fixture",
            ),
        ),
        verdict=verdict,
        authorized_next_action="collect evidence",
        forbidden_next_actions=("claim performance",),
    )


class _Verification:
    def model_dump(self, *, mode: str) -> dict[str, str]:
        assert mode == "json"
        return {"verdict": "BLOCKED_EVIDENCE"}


def test_repo_discovery_and_memory_schema_commands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = _repo(tmp_path)
    nested = repo / "a" / "b"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)
    assert _repo_root(None) == repo
    assert _repo_root(str(repo)) == repo
    assert main(["--repo", str(repo), "memory", "verify"]) == 0
    assert json.loads(capsys.readouterr().out)["event_count"] == 0

    assert main(["--repo", str(repo), "schemas", "export"]) == 0
    capsys.readouterr()
    assert main(["--repo", str(repo), "schemas", "check"]) == 0
    assert "SCHEMAS_VERIFIED" in capsys.readouterr().out
    schema = next((repo / "protocol" / "schemas").glob("*.json"))
    schema.write_text("{}\n")
    with pytest.raises(SystemExit):
        main(["--repo", str(repo), "schemas", "check"])


def test_trust_ledger_and_memory_prefix_commands(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = _repo(tmp_path)
    assert main(["--repo", str(repo), "trust", "init-iter000"]) == 0
    anchor_data = json.loads(capsys.readouterr().out)
    assert len(anchor_data["signer_public_key"]) == 64
    assert main(["--repo", str(repo), "trust", "init-iter000-verification"]) == 0
    verification_anchor = json.loads(capsys.readouterr().out)
    assert verification_anchor["anchor_id"] == "iter000-verification-correction-001"
    assert verification_anchor["signer_public_key"] != anchor_data["signer_public_key"]

    key_data = (repo / ".local" / "keys" / "iter000.ed25519").read_bytes()
    key = SigningKey(key_data)
    ledger_path = repo / "proof" / "events.jsonl"
    head_path = repo / "proof" / "head.json"
    ledger = SignedLedger(ledger_path, head_path, key)
    ledger.append(
        run_id="run-1",
        event_type="run-started",
        payload={},
        runtime=runtime_identity(),
    )
    ledger.append(
        run_id="run-1",
        event_type="run-failed",
        payload={"reason": "fixture"},
        runtime=runtime_identity(),
    )
    assert (
        main(
            [
                "--repo",
                str(repo),
                "ledger",
                "verify",
                "proof/events.jsonl",
                "proof/head.json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["event_count"] == 2

    base = tmp_path / "base.jsonl"
    base.write_text("")
    assert (
        main(
            [
                "--repo",
                str(repo),
                "memory",
                "verify-prefix",
                str(base),
            ]
        )
        == 0
    )


def test_dataset_mission_and_experiment_commands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = _repo(tmp_path)
    raw_root = repo / "fixture-raw"
    lock, _ = create_adapt_source(raw_root)
    lock_path = repo / "protocol" / "datasets" / "nasa_adapt_v1.json"
    lock_path.parent.mkdir(parents=True)
    lock_path.write_bytes(canonical_json_pretty(lock))
    assert (
        main(
            [
                "--repo",
                str(repo),
                "datasets",
                "fetch-adapt",
                "--raw-root",
                "fixture-raw",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)[0]["verified"] is True

    mission = MissionValidation(
        passed=False,
        checks=(ValidationCheck(check_id="fixture", passed=False, detail="blocked"),),
    )
    monkeypatch.setattr(cli_module, "validate_mission", lambda _repo: mission)
    assert main(["--repo", str(repo), "mission", "validate"]) == 1
    capsys.readouterr()

    monkeypatch.setattr(cli_module, "run_iter000", lambda *_args, **_kwargs: _report())
    assert main(["--repo", str(repo), "experiment", "iter000"]) == 0
    capsys.readouterr()
    monkeypatch.setattr(
        cli_module,
        "run_iter000",
        lambda *_args, **_kwargs: _report("INVALID"),
    )
    assert main(["--repo", str(repo), "experiment", "iter000"]) == 2
    capsys.readouterr()
    monkeypatch.setattr(
        cli_module,
        "run_iter000_amendment_001",
        lambda *_args, **_kwargs: _report(),
    )
    assert main(["--repo", str(repo), "experiment", "iter000-amendment-001"]) == 0
    capsys.readouterr()

    monkeypatch.setattr(
        cli_module,
        "verify_iter000_proof_bundle",
        lambda *_args, **_kwargs: _Verification(),
    )
    assert main(["--repo", str(repo), "experiment", "verify-iter000"]) == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == "BLOCKED_EVIDENCE"
    assert main(["--repo", str(repo), "experiment", "verify-iter000-amendment-001"]) == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == "BLOCKED_EVIDENCE"

    corrected_commands: list[tuple[str, ...]] = []

    def corrected_verification(
        _repo: Path,
        *,
        command: tuple[str, ...],
    ) -> _Verification:
        corrected_commands.append(command)
        return _Verification()

    monkeypatch.setattr(
        cli_module,
        "verify_iter000_proof_bundle_correction_001",
        corrected_verification,
    )
    monkeypatch.setattr(cli_module, "validate_mission", lambda _repo: mission)
    with pytest.raises(SystemExit, match="1"):
        main(
            [
                "--repo",
                str(repo),
                "experiment",
                "verify-iter000-amendment-001-correction-001",
            ]
        )
    assert corrected_commands == []
    capsys.readouterr()

    passed_mission = MissionValidation(passed=True, checks=())
    monkeypatch.setattr(cli_module, "validate_mission", lambda _repo: passed_mission)
    assert (
        main(
            [
                "--repo",
                str(repo),
                "experiment",
                "verify-iter000-amendment-001-correction-001",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["verdict"] == "BLOCKED_EVIDENCE"
    assert corrected_commands == [
        (
            "fieldtrue",
            "experiment",
            "verify-iter000-amendment-001-correction-001",
        )
    ]


def test_repo_discovery_fails_outside_a_mission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(FileNotFoundError, match="inside"):
        _repo_root(None)
