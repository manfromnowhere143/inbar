"""Command-line entry point for local mission control."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import NoReturn

from fieldtrue.acquisition import (
    AcquisitionAuditError,
    audit_acquisition,
    load_acquisition_contract,
    verify_preregistration_binding,
    write_admission_output,
)
from fieldtrue.adapters.adapt import (
    fetch_adapt_dataset,
    load_adapt_lock,
)
from fieldtrue.control_authority import ControlAuthorityError, verify_admission_control_bundle
from fieldtrue.experiment import run_iter000, run_iter000_amendment_001
from fieldtrue.handoff import HandoffError, check_handoff, write_handoff
from fieldtrue.memory import verify_memory, verify_memory_prefix
from fieldtrue.mission import validate_mission
from fieldtrue.receipts import (
    load_or_create_signing_key,
    load_signer_anchor,
    verify_ledger,
    write_signer_anchor,
)
from fieldtrue.schemas import export_schemas, verify_schemas
from fieldtrue.verification import (
    initialize_iter000_verification_signer,
    verify_iter000_proof_bundle,
    verify_iter000_proof_bundle_correction_001,
)


def _repo_root(raw: str | None) -> Path:
    if raw is not None:
        return Path(raw).expanduser().resolve()
    candidate = Path.cwd().resolve()
    for path in (candidate, *candidate.parents):
        if (path / "mission" / "contract.json").is_file():
            return path
    raise FileNotFoundError("run inside the mission repository or pass --repo")


def _fail(message: str, code: int = 1) -> NoReturn:
    print(message, file=sys.stderr)
    raise SystemExit(code)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="inbar")
    parser.add_argument("--repo", help="Mission repository root")
    groups = parser.add_subparsers(dest="group", required=True)

    mission = groups.add_parser("mission")
    mission_validate = mission.add_subparsers(dest="action", required=True).add_parser("validate")
    mission_validate.add_argument(
        "--expect-failure",
        action="append",
        default=[],
        metavar="CHECK_ID",
        help="return success only when these exact validation checks fail",
    )

    schemas = groups.add_parser("schemas")
    schema_actions = schemas.add_subparsers(dest="action", required=True)
    schema_actions.add_parser("export")
    schema_actions.add_parser("check")

    memory = groups.add_parser("memory")
    memory_actions = memory.add_subparsers(dest="action", required=True)
    memory_actions.add_parser("verify")
    memory_prefix = memory_actions.add_parser("verify-prefix")
    memory_prefix.add_argument("base_path")

    handoff = groups.add_parser("handoff")
    handoff_actions = handoff.add_subparsers(dest="action", required=True)
    handoff_actions.add_parser("render")
    handoff_actions.add_parser("check")

    ledger = groups.add_parser("ledger")
    ledger_verify = ledger.add_subparsers(dest="action", required=True).add_parser("verify")
    ledger_verify.add_argument("ledger_path")
    ledger_verify.add_argument("head_path")
    ledger_verify.add_argument("--anchor-path", default="protocol/trust/iter000_signer_anchor.json")

    trust = groups.add_parser("trust")
    trust_actions = trust.add_subparsers(dest="action", required=True)
    trust_actions.add_parser("init-iter000")
    trust_actions.add_parser("init-iter000-verification")

    datasets = groups.add_parser("datasets")
    fetch = datasets.add_subparsers(dest="action", required=True).add_parser("fetch-adapt")
    fetch.add_argument("--raw-root")

    acquisition = groups.add_parser("acquisition")
    acquisition_audit = acquisition.add_subparsers(dest="action", required=True).add_parser("audit")
    acquisition_audit.add_argument("--contract", required=True)
    acquisition_audit.add_argument("--input-root", required=True)
    acquisition_audit.add_argument("--output-root", required=True)

    experiment = groups.add_parser("experiment")
    experiment_actions = experiment.add_subparsers(dest="action", required=True)
    experiment_actions.add_parser("iter000")
    experiment_actions.add_parser("iter000-amendment-001")
    experiment_actions.add_parser("verify-iter000")
    experiment_actions.add_parser("verify-iter000-amendment-001")
    experiment_actions.add_parser("verify-iter000-amendment-001-correction-001")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    repo = _repo_root(arguments.repo)
    if arguments.group == "mission" and arguments.action == "validate":
        mission_report = validate_mission(repo)
        print(json.dumps(mission_report.model_dump(mode="json"), indent=2, sort_keys=True))
        if arguments.expect_failure:
            expected = set(arguments.expect_failure)
            if len(expected) != len(arguments.expect_failure):
                _fail("expected mission failure IDs must be unique", 2)
            observed = {check.check_id for check in mission_report.checks if not check.passed}
            return 0 if observed == expected else 1
        return 0 if mission_report.passed else 1
    if arguments.group == "schemas" and arguments.action == "export":
        paths = export_schemas(repo)
        print("\n".join(path.relative_to(repo).as_posix() for path in paths))
        return 0
    if arguments.group == "schemas" and arguments.action == "check":
        errors = verify_schemas(repo)
        if errors:
            _fail("\n".join(errors))
        print("SCHEMAS_VERIFIED")
        return 0
    if arguments.group == "memory" and arguments.action == "verify":
        count, head = verify_memory(repo / "memory" / "research_engine_extraction.jsonl")
        print(json.dumps({"event_count": count, "head_hash": head}, sort_keys=True))
        return 0
    if arguments.group == "memory" and arguments.action == "verify-prefix":
        base_path = Path(arguments.base_path)
        base_count, current_count = verify_memory_prefix(
            base_path,
            repo / "memory" / "research_engine_extraction.jsonl",
        )
        print(json.dumps({"base_count": base_count, "current_count": current_count}))
        return 0
    if arguments.group == "handoff" and arguments.action == "render":
        try:
            path = write_handoff(repo)
        except HandoffError as error:
            _fail(str(error))
        print(path.relative_to(repo).as_posix())
        return 0
    if arguments.group == "handoff" and arguments.action == "check":
        try:
            check_handoff(repo)
        except HandoffError as error:
            _fail(str(error))
        print("HANDOFF_VERIFIED")
        return 0
    if arguments.group == "ledger" and arguments.action == "verify":
        ledger_path = Path(arguments.ledger_path)
        head_path = Path(arguments.head_path)
        anchor_path = Path(arguments.anchor_path)
        ledger_report = verify_ledger(
            ledger_path if ledger_path.is_absolute() else repo / ledger_path,
            head_path if head_path.is_absolute() else repo / head_path,
            expected_signer_public_key=load_signer_anchor(
                anchor_path if anchor_path.is_absolute() else repo / anchor_path
            ).signer_public_key,
        )
        print(json.dumps(ledger_report.model_dump(mode="json"), indent=2, sort_keys=True))
        return 0
    if arguments.group == "trust" and arguments.action == "init-iter000":
        key = load_or_create_signing_key(repo / ".local" / "keys" / "iter000.ed25519")
        anchor = write_signer_anchor(
            repo / "protocol" / "trust" / "iter000_signer_anchor.json",
            key,
            anchor_id="iter000-execution-ledger",
            ledger_scope="iter000_nasa_adapt_corpus_readiness",
        )
        print(json.dumps(anchor.model_dump(mode="json"), indent=2, sort_keys=True))
        return 0
    if arguments.group == "trust" and arguments.action == "init-iter000-verification":
        anchor = initialize_iter000_verification_signer(repo)
        print(json.dumps(anchor.model_dump(mode="json"), indent=2, sort_keys=True))
        return 0
    if arguments.group == "datasets" and arguments.action == "fetch-adapt":
        lock = load_adapt_lock(repo / "protocol" / "datasets" / "nasa_adapt_v1.json")
        raw_root = repo / "data" / "raw" / lock.dataset_id
        if arguments.raw_root:
            requested_root = Path(arguments.raw_root)
            raw_root = requested_root if requested_root.is_absolute() else repo / requested_root
        receipts = fetch_adapt_dataset(lock, raw_root)
        print(json.dumps([item.model_dump(mode="json") for item in receipts], indent=2))
        return 0
    if arguments.group == "acquisition" and arguments.action == "audit":
        contract_path = Path(arguments.contract)
        input_root = Path(arguments.input_root)
        output_root = Path(arguments.output_root)
        contract_path = contract_path if contract_path.is_absolute() else repo / contract_path
        input_root = input_root if input_root.is_absolute() else repo / input_root
        output_root = output_root if output_root.is_absolute() else repo / output_root
        try:
            contract = load_acquisition_contract(contract_path.resolve())
            verify_preregistration_binding(repo, contract)
            resolved_input = input_root.resolve()
            resolved_output = output_root.resolve()
            control_receipt = verify_admission_control_bundle(repo, resolved_input, contract)
            source_closure = verify_preregistration_binding(
                repo,
                contract,
                control_receipt.execution_commit,
            )
            if resolved_output.is_relative_to(resolved_input):
                raise AcquisitionAuditError("output root cannot be inside the acquisition input")
            admission = audit_acquisition(contract, resolved_input)
            if (
                verify_preregistration_binding(
                    repo,
                    contract,
                    control_receipt.execution_commit,
                )
                != source_closure
            ):
                raise AcquisitionAuditError("acquisition source closure changed during audit")
            write_admission_output(resolved_output, admission)
        except (AcquisitionAuditError, ControlAuthorityError, OSError) as error:
            _fail(str(error), 3)
        print(json.dumps(admission.model_dump(mode="json"), indent=2, sort_keys=True))
        if admission.verdict == "PASS_PILOT":
            return 0
        if admission.verdict in {
            "BLOCKED_ACQUISITION",
            "BLOCKED_RIGHTS",
            "KILL_CONSTRUCT",
        }:
            return 2
        return 3
    if arguments.group == "experiment" and arguments.action == "iter000":
        command = tuple(
            ["fieldtrue", "experiment", "iter000"] if argv is None else ["fieldtrue", *argv]
        )
        experiment_report = run_iter000(repo, command=command)
        print(json.dumps(experiment_report.model_dump(mode="json"), indent=2, sort_keys=True))
        return 2 if experiment_report.verdict == "INVALID" else 0
    if arguments.group == "experiment" and arguments.action == "iter000-amendment-001":
        command = tuple(
            ["fieldtrue", "experiment", "iter000-amendment-001"]
            if argv is None
            else ["fieldtrue", *argv]
        )
        experiment_report = run_iter000_amendment_001(repo, command=command)
        print(json.dumps(experiment_report.model_dump(mode="json"), indent=2, sort_keys=True))
        return 2 if experiment_report.verdict == "INVALID" else 0
    if arguments.group == "experiment" and arguments.action == "verify-iter000":
        verification = verify_iter000_proof_bundle(
            repo / "experiments" / "iter000_nasa_adapt_corpus_readiness" / "proof" / "attempt_000",
            signer_anchor_path=(repo / "protocol" / "trust" / "iter000_signer_anchor.json"),
        )
        print(json.dumps(verification.model_dump(mode="json"), indent=2, sort_keys=True))
        return 0
    if arguments.group == "experiment" and arguments.action == "verify-iter000-amendment-001":
        verification = verify_iter000_proof_bundle(
            repo / "experiments" / "iter000_nasa_adapt_corpus_readiness" / "proof" / "attempt_001",
            signer_anchor_path=(repo / "protocol" / "trust" / "iter000_signer_anchor.json"),
            authority_specification_path=(
                repo / "protocol" / "attempt_authorities" / "iter000_001.json"
            ),
        )
        print(json.dumps(verification.model_dump(mode="json"), indent=2, sort_keys=True))
        return 0
    if (
        arguments.group == "experiment"
        and arguments.action == "verify-iter000-amendment-001-correction-001"
    ):
        mission_report = validate_mission(repo)
        if not mission_report.passed:
            failures = [check.check_id for check in mission_report.checks if not check.passed]
            _fail(f"mission preflight failed: {', '.join(failures)}")
        corrected_verification = verify_iter000_proof_bundle_correction_001(
            repo,
            command=(
                "fieldtrue",
                "experiment",
                "verify-iter000-amendment-001-correction-001",
            ),
        )
        print(json.dumps(corrected_verification.model_dump(mode="json"), indent=2, sort_keys=True))
        return 0
    _fail("unsupported command")


if __name__ == "__main__":
    raise SystemExit(main())
