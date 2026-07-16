from __future__ import annotations

import importlib
import json
import re
import shutil
import sys
from pathlib import Path
from types import ModuleType

import pytest

import fieldtrue.handoff as handoff_module
from fieldtrue.handoff import HandoffError, check_handoff, render_handoff, write_handoff
from fieldtrue.memory import MemoryStatus, ResearchMemoryRecord, load_memory_records
from fieldtrue.mission import MissionValidation, ValidationCheck

_LEGACY_CHECKPOINT_EVENT_ID = "iter001-shortcut-v2-implementation-checkpoint-v1"
_LEGACY_HANDOFF_EVENT_ID = "iter001-shortcut-v2-activation-gates-v1"


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def memory_records() -> tuple[ResearchMemoryRecord, ...]:
    return load_memory_records(_project_root() / "memory" / "research_engine_extraction.jsonl")


@pytest.fixture
def handoff_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "mission-clone"
    inputs: dict[str, dict[str, object]] = {
        "mission/contract.json": {
            "mission_id": "inbar",
            "name": "Inbar",
            "owner": "Daniel Wahnich",
            "legacy_protocol_namespace": "fieldtrue",
            "research_engine_policy": (
                "deferred_to_separate_repository_after_multiple_complete_cycles"
            ),
            "source_digest_fixture": "one",
        },
        "mission/loop.json": {
            "current_stage": "corpus_qualification",
            "publication_transition": {"status": "blocked"},
        },
        "mission/name.json": {
            "canonical_slug": "inbar",
            "status": "internally_adopted_pending_professional_clearance",
        },
        "protocol/acquisition/iter001_contract.json": {
            "iteration_id": "iter001_physical_causal_evidence_acquisition",
            "control_authority_status": "bootstrap",
        },
    }
    for relative, value in inputs.items():
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    memory_path = repo / "memory" / "research_engine_extraction.jsonl"
    memory_path.parent.mkdir(parents=True)
    memory_path.write_text("fixture memory bytes\n", encoding="utf-8")
    for binding in handoff_module._BOUND_FIELDTRUE_MODULES:
        source_path = repo / binding.repository_path
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_bytes(binding.imported_bytes)
    source_root = repo / "src" / "fieldtrue"
    (source_root / "second.py").write_text("VALUE = 2\n", encoding="utf-8")
    schema_root = repo / "protocol" / "schemas"
    schema_root.mkdir(parents=True)
    (schema_root / "alpha.schema.json").write_bytes(b'{"title":"alpha"}\n')
    (schema_root / "beta.schema.json").write_bytes(b'{"title":"beta"}\n')
    recovery_inputs = {
        ".github/workflows/ci.yml": b"name: fixture-ci\n",
        "README.md": b"# Fixture mission\n",
        "claims/registry.jsonl": b'{"claim":"blocked"}\n',
        "docs/ARCHITECTURE.md": b"# Architecture\n",
        "proofs/authority.txt": b"no authority\n",
        "scripts/verify.py": b"VALUE = 'verify'\n",
        "tests/test_fixture.py": b"def test_fixture(): pass\n",
    }
    for relative, content in recovery_inputs.items():
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return repo


def _mission_report(
    *,
    extra_failures: tuple[str, ...] = (),
    omit_expected: bool = False,
) -> MissionValidation:
    check_ids = list(handoff_module._EXPECTED_MISSION_CHECK_IDS)
    if omit_expected:
        check_ids[check_ids.index("iter001-acquisition-contract")] = "fixture-replacement-check"
    for index, check_id in enumerate(extra_failures, start=1):
        check_ids[-index] = check_id
    checks = []
    for check_id in check_ids:
        if check_id == "iter001-acquisition-contract":
            checks.append(
                ValidationCheck(
                    check_id=check_id,
                    passed=False,
                    detail=(
                        "Iteration 001 acquisition contract failed: canonical control authority "
                        "is not sealed"
                    ),
                )
            )
        elif check_id in extra_failures:
            checks.append(ValidationCheck(check_id=check_id, passed=False, detail="unexpected"))
        else:
            checks.append(ValidationCheck(check_id=check_id, passed=True, detail="verified"))
    assert len(checks) == 22
    return MissionValidation(passed=all(check.passed for check in checks), checks=tuple(checks))


def _install_verified_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    memory_records: tuple[ResearchMemoryRecord, ...],
    *,
    report: MissionValidation | None = None,
    schema_errors: list[str] | None = None,
) -> None:
    monkeypatch.setattr(handoff_module, "load_memory_records_bytes", lambda _data: memory_records)
    monkeypatch.setattr(
        handoff_module,
        "validate_mission",
        lambda _repo: report or _mission_report(),
    )
    monkeypatch.setattr(
        handoff_module,
        "schema_documents",
        lambda: {
            "alpha.schema.json": b'{"title":"alpha"}\n',
            "beta.schema.json": b'{"title":"beta"}\n',
        },
    )
    if schema_errors is not None:
        monkeypatch.setattr(
            handoff_module,
            "schema_documents",
            lambda: {
                "alpha.schema.json": b'{"title":"changed"}\n',
                "beta.schema.json": b'{"title":"beta"}\n',
            },
        )


def _input_digest(document: bytes) -> str:
    match = re.search(rb"Generated-input digest: `([0-9a-f]{64})`", document)
    assert match is not None
    return match.group(1).decode("ascii")


def _replace_record(
    records: tuple[ResearchMemoryRecord, ...],
    event_id: str,
    **updates: object,
) -> tuple[ResearchMemoryRecord, ...]:
    return tuple(
        record.model_copy(update=updates) if record.event_id == event_id else record
        for record in records
    )


def _selected_recovery_records(
    records: tuple[ResearchMemoryRecord, ...],
) -> tuple[ResearchMemoryRecord, ResearchMemoryRecord]:
    handoff = max(
        (
            record
            for record in records
            if record.mission_id == "inbar"
            and record.event_type == handoff_module.MemoryEventType.HANDOFF
        ),
        key=lambda record: record.sequence,
    )
    checkpoint_id = handoff.links["checkpoint"]
    checkpoint = next(record for record in records if record.event_id == checkpoint_id)
    return checkpoint, handoff


def _legacy_recovery_memory(
    records: tuple[ResearchMemoryRecord, ...],
) -> tuple[ResearchMemoryRecord, ...]:
    legacy_handoff = next(
        record for record in records if record.event_id == _LEGACY_HANDOFF_EVENT_ID
    )
    engine_boundary = next(
        record
        for record in records
        if record.event_id == "future-research-engine-shortcut-v2-lessons-v1"
    )
    cutoff = max(legacy_handoff.sequence, engine_boundary.sequence)
    return tuple(record for record in records if record.sequence <= cutoff)


def _versioned_recovery_records(
    records: tuple[ResearchMemoryRecord, ...],
) -> tuple[ResearchMemoryRecord, ResearchMemoryRecord]:
    prior_checkpoint, prior_handoff = _selected_recovery_records(records)
    validation = {
        **prior_checkpoint.payload["validation"],
        "mission_check_ids": list(handoff_module._EXPECTED_MISSION_CHECK_IDS),
    }
    checkpoint = prior_checkpoint.model_copy(
        update={
            "sequence": records[-1].sequence + 1,
            "event_id": "fixture-versioned-checkpoint",
            "stage": "mission-handoff",
            "payload": {
                **prior_checkpoint.payload,
                "action": handoff_module.RECOVERY_CHECKPOINT_ACTION,
                "authority_effect": handoff_module.RECOVERY_CHECKPOINT_AUTHORITY_EFFECT,
                "handoff_contract": "inbar.handoff-checkpoint.v1",
                "outcome": handoff_module.RECOVERY_CHECKPOINT_OUTCOME,
                "validation": validation,
            },
        }
    )
    handoff = prior_handoff.model_copy(
        update={
            "sequence": checkpoint.sequence + 1,
            "event_id": "fixture-versioned-handoff",
            "stage": "mission-handoff",
            "links": {
                "checkpoint": checkpoint.event_id,
                "engine_boundary": "future-research-engine-shortcut-v2-lessons-v1",
                "source_verdict": "iter001-public-substrate-verdict-v1",
            },
            "payload": {
                **prior_handoff.payload,
                "forbidden_until_activation": list(handoff_module._CANONICAL_FORBIDDEN_ACTIONS),
                "handoff_contract": "inbar.handoff-state.v1",
                "next_action": handoff_module.RECOVERY_HANDOFF_NEXT_ACTION,
                "state": handoff_module.RECOVERY_HANDOFF_STATE,
            },
        }
    )
    return checkpoint, handoff


def test_versioned_recovery_text_is_exactly_frozen() -> None:
    assert handoff_module.RECOVERY_CHECKPOINT_ACTION == (
        "Hardened the deterministic Inbar recovery contract and verified its internal consistency."
    )
    assert handoff_module.RECOVERY_CHECKPOINT_OUTCOME == (
        "Recovery inputs and the blocked mission state are reproducibly bound to committed "
        "evidence."
    )
    assert handoff_module.RECOVERY_CHECKPOINT_AUTHORITY_EFFECT == (
        "No authority was granted; iter001-acquisition-contract remains blocked."
    )
    assert handoff_module.RECOVERY_HANDOFF_STATE == (
        "Inbar remains in bootstrap with iter001-acquisition-contract blocked and no mission "
        "authority active."
    )
    assert handoff_module.RECOVERY_HANDOFF_NEXT_ACTION == (
        "Complete and prospectively seal iter001-acquisition-contract before exercising any "
        "denied authority."
    )


def test_render_is_deterministic_clone_independent_and_self_reference_free(
    handoff_repo: Path,
    tmp_path: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    stale = handoff_repo / "HANDOFF.md"
    stale.write_text("UNIQUE_EXISTING_HANDOFF_SENTINEL\n", encoding="utf-8")

    first = render_handoff(handoff_repo)
    second = render_handoff(handoff_repo)

    clone = tmp_path / "different" / "clone-path"
    clone.parent.mkdir(parents=True)
    shutil.copytree(handoff_repo, clone)
    (clone / "README.md").chmod(0o600)
    (clone / "docs").chmod(0o700)
    cloned = render_handoff(clone)

    assert first == second == cloned
    assert b"UNIQUE_EXISTING_HANDOFF_SENTINEL" not in first
    assert handoff_repo.as_posix().encode() not in first
    assert clone.as_posix().encode() not in first
    assert b"Generated at" not in first
    assert b"Generated from commit" not in first
    assert re.search(rb"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}", first) is None
    assert b"- Branch:" not in first
    assert b"Git remotes" not in first
    assert b"github.com" not in first
    assert re.search(rb"\bHEAD\b", first) is None


def test_render_includes_current_memory_checkpoint_and_public_substrate_finding(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    checkpoint, handoff = _selected_recovery_records(memory_records)

    document = render_handoff(handoff_repo).decode("utf-8")

    assert "`KILL_PUBLIC_SUBSTRATE`" in document
    source_record = next(
        item for item in memory_records if item.event_id == "iter001-public-substrate-verdict-v1"
    )
    assert f"Source verdict event: `{source_record.event_id}`" in document
    assert f"Source verdict event hash: `{source_record.event_hash}`" in document
    assert f"Source verdict summary: {source_record.summary}" in document
    assert (
        "Source architecture: physical admission, causal laboratory, independent reality"
        in document
    )
    assert "Compute consequence: GPU training remains blocked." in document
    assert handoff.event_id in document
    assert checkpoint.event_id in document
    assert checkpoint.payload["implementation_commit"] in document
    validation = checkpoint.payload["validation"]
    assert f"{validation['tests_passed']} passed, {validation['tests_skipped']} skipped" in document
    assert f"{validation['branch_coverage_percent']:.2f} percent" in document
    assert f"Research-memory events: {len(memory_records)}" in document
    assert memory_records[-1].event_hash in document
    assert "Canonical control authority: `bootstrap`" in document
    assert "Publication transition: `blocked`" in document


def test_source_digest_is_deterministic_and_binds_unrendered_source_bytes(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    before = render_handoff(handoff_repo)
    contract_path = handoff_repo / "mission" / "contract.json"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    contract["source_digest_fixture"] = "two"
    contract_path.write_text(
        json.dumps(contract, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    after = render_handoff(handoff_repo)

    assert _input_digest(before) != _input_digest(after)
    assert before.replace(_input_digest(before).encode(), b"DIGEST") == after.replace(
        _input_digest(after).encode(), b"DIGEST"
    )


def test_recovery_digest_binds_claims_outside_the_rendered_fields(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    before = render_handoff(handoff_repo)
    claim_path = handoff_repo / "claims" / "registry.jsonl"
    claim_path.write_bytes(claim_path.read_bytes() + b'{"claim":"still-blocked"}\n')

    after = render_handoff(handoff_repo)

    assert _input_digest(before) != _input_digest(after)
    assert before.replace(_input_digest(before).encode(), b"DIGEST") == after.replace(
        _input_digest(after).encode(), b"DIGEST"
    )


def test_recovery_digest_binds_empty_directory_inventory(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    before = render_handoff(handoff_repo)
    (handoff_repo / "proofs" / "empty-proof-surface").mkdir()

    after = render_handoff(handoff_repo)

    assert _input_digest(before) != _input_digest(after)


def test_render_binds_the_imported_renderer_source_to_repository_source(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    (handoff_repo / "src" / "fieldtrue" / "handoff.py").write_text("VALUE = 1\n", encoding="utf-8")

    with pytest.raises(HandoffError, match="imported handoff renderer source differs"):
        render_handoff(handoff_repo)


def test_render_rejects_imported_renderer_code_that_differs_from_source(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    module_path = Path(handoff_module.__file__).resolve(strict=True)
    monkeypatch.setattr(
        handoff_module,
        "_IMPORTED_MODULE_CODE",
        compile("VALUE = 1\n", str(module_path), "exec"),
    )

    with pytest.raises(HandoffError, match="executing handoff renderer code differs"):
        render_handoff(handoff_repo)


def test_render_rejects_bound_dependency_source_mismatch(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    dependency = next(
        item for item in handoff_module._BOUND_FIELDTRUE_MODULES if item.name == "fieldtrue.memory"
    )
    dependency_path = handoff_repo / dependency.repository_path
    dependency_path.write_bytes(dependency_path.read_bytes() + b"# changed dependency\n")

    with pytest.raises(HandoffError, match=r"imported Fieldtrue module source differs.*memory"):
        render_handoff(handoff_repo)


def test_render_rejects_bound_dependency_loader_code_mismatch(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    changed_bindings = tuple(
        binding._replace(loader_code=compile("VALUE = 1\n", binding.imported_path, "exec"))
        if binding.name == "fieldtrue.memory"
        else binding
        for binding in handoff_module._BOUND_FIELDTRUE_MODULES
    )
    monkeypatch.setattr(handoff_module, "_BOUND_FIELDTRUE_MODULES", changed_bindings)

    with pytest.raises(HandoffError, match=r"loader code differs.*memory"):
        render_handoff(handoff_repo)


def test_render_rejects_new_unbound_fieldtrue_module(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)

    def validation(_repo: Path) -> MissionValidation:
        monkeypatch.setitem(
            sys.modules,
            "fieldtrue.unbound_handoff_fixture",
            ModuleType("fieldtrue.unbound_handoff_fixture"),
        )
        return _mission_report()

    monkeypatch.setattr(handoff_module, "validate_mission", validation)

    with pytest.raises(HandoffError, match="unbound Fieldtrue modules loaded"):
        render_handoff(handoff_repo)


def test_render_rejects_unbound_fieldtrue_import_through_meta_path(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)

    class VirtualLoader:
        def create_module(self, spec: object) -> None:
            del spec
            return None

        def exec_module(self, module: ModuleType) -> None:
            del module

    class VirtualFinder:
        def find_spec(
            self,
            fullname: str,
            path: object,
            target: object = None,
        ) -> object:
            del path, target
            if fullname == "fieldtrue.unbound_import_fixture":
                return importlib.util.spec_from_loader(fullname, VirtualLoader())
            return None

    monkeypatch.setattr(sys, "meta_path", [*sys.meta_path, VirtualFinder()])

    def validation(_repo: Path) -> MissionValidation:
        importlib.import_module("fieldtrue.unbound_import_fixture")
        return _mission_report()

    monkeypatch.setattr(handoff_module, "validate_mission", validation)

    with pytest.raises(HandoffError, match="unbound Fieldtrue module import during handoff"):
        render_handoff(handoff_repo)


def test_write_and_check_round_trip_and_detect_stale_document(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)

    path = write_handoff(handoff_repo)

    assert path == handoff_repo / "HANDOFF.md"
    assert path.read_bytes() == render_handoff(handoff_repo)
    check_handoff(handoff_repo)
    path.write_bytes(path.read_bytes() + b"manual edit\n")
    with pytest.raises(HandoffError, match=r"HANDOFF\.md is stale"):
        check_handoff(handoff_repo)


def test_check_rejects_missing_and_symbolic_link_handoff(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    with pytest.raises(HandoffError, match=r"HANDOFF\.md is unavailable"):
        check_handoff(handoff_repo)
    target = handoff_repo / "target.md"
    target.write_text("not authoritative\n", encoding="utf-8")
    (handoff_repo / "HANDOFF.md").symlink_to(target)
    with pytest.raises(HandoffError, match=r"HANDOFF\.md is unavailable"):
        check_handoff(handoff_repo)


def test_render_rejects_symbolic_link_parent_component(
    handoff_repo: Path,
    tmp_path: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    outside = tmp_path / "outside-mission"
    (handoff_repo / "mission").replace(outside)
    (handoff_repo / "mission").symlink_to(outside, target_is_directory=True)

    with pytest.raises(HandoffError, match="traverses a symbolic link"):
        render_handoff(handoff_repo)


def test_check_rejects_handoff_change_during_render(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    write_handoff(handoff_repo)
    original_read = handoff_module._read_regular_file
    handoff_reads = 0

    def changing_read(repo_root: Path, relative: str, label: str) -> bytes:
        nonlocal handoff_reads
        data = original_read(repo_root, relative, label)
        if relative == "HANDOFF.md":
            handoff_reads += 1
            if handoff_reads == 2:
                return data + b"concurrent edit\n"
        return data

    monkeypatch.setattr(handoff_module, "_read_regular_file", changing_read)

    with pytest.raises(HandoffError, match=r"HANDOFF\.md is stale"):
        check_handoff(handoff_repo)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("missing", "does not link a checkpoint"),
        ("unknown", "checkpoint link is not an earlier event"),
        ("future", "checkpoint link is not an earlier event"),
        ("blocked", "must link a passing execution checkpoint"),
    ],
)
def test_render_rejects_missing_or_invalid_checkpoint_links(
    mutation: str,
    message: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint, handoff = _selected_recovery_records(memory_records)
    if mutation == "missing":
        records = _replace_record(memory_records, handoff.event_id, links={})
    elif mutation == "unknown":
        records = _replace_record(memory_records, handoff.event_id, links={"checkpoint": "absent"})
    elif mutation == "future":
        records = _replace_record(
            memory_records,
            checkpoint.event_id,
            sequence=memory_records[-1].sequence + 1,
        )
    else:
        records = _replace_record(memory_records, checkpoint.event_id, status=MemoryStatus.BLOCKED)
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(HandoffError, match=message):
        render_handoff(handoff_repo)


@pytest.mark.parametrize(
    ("target", "payload_update", "message"),
    [
        (
            "handoff",
            {"remaining_gates": []},
            "payload violates",
        ),
        (
            "source",
            {"product_wedge": "line one\nline two"},
            "must be one trimmed line",
        ),
        (
            "checkpoint",
            {"unexpected": "not admitted"},
            "payload violates",
        ),
        (
            "source",
            {"finding": "PASS_PUBLIC_SUBSTRATE"},
            "payload violates",
        ),
    ],
)
def test_render_rejects_malformed_display_payloads(
    target: str,
    payload_update: dict[str, object],
    message: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint, handoff = _selected_recovery_records(memory_records)
    event_id = {
        "checkpoint": checkpoint.event_id,
        "handoff": handoff.event_id,
        "source": "iter001-public-substrate-verdict-v1",
    }[target]
    record = next(item for item in memory_records if item.event_id == event_id)
    payload = {**record.payload, **payload_update}
    records = _replace_record(memory_records, event_id, payload=payload)
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(HandoffError, match=message):
        render_handoff(handoff_repo)


def test_render_rejects_coerced_checkpoint_metrics(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint, _handoff = _selected_recovery_records(memory_records)
    validation = {**checkpoint.payload["validation"], "tests_passed": "513"}
    payload = {**checkpoint.payload, "validation": validation}
    records = _replace_record(memory_records, checkpoint.event_id, payload=payload)
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(HandoffError, match="payload violates its exact contract"):
        render_handoff(handoff_repo)


def test_render_rejects_a_corrected_selected_event(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint, handoff = _versioned_recovery_records(memory_records)
    correction = memory_records[59].model_copy(
        update={
            "sequence": checkpoint.sequence + 1,
            "event_id": "fixture-handoff-correction",
            "corrects_event_id": checkpoint.event_id,
        }
    )
    handoff = handoff.model_copy(update={"sequence": correction.sequence + 1})
    records = (*memory_records, checkpoint, correction, handoff)
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(HandoffError, match="selected recovery events were corrected"):
        render_handoff(handoff_repo)


def test_render_rejects_an_unversioned_newer_handoff(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _checkpoint, prior = _selected_recovery_records(memory_records)
    payload = {**prior.payload, "handoff_contract": None}
    newest = prior.model_copy(
        update={
            "sequence": memory_records[-1].sequence + 1,
            "event_id": "fixture-newest-valid-handoff",
            "payload": payload,
        }
    )
    records = (*memory_records, newest)
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(HandoffError, match="lacks the versioned handoff contract"):
        render_handoff(handoff_repo)


def test_render_selects_a_versioned_commit_bound_newer_handoff(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint, newest = _versioned_recovery_records(memory_records)
    _install_verified_dependencies(monkeypatch, (*memory_records, checkpoint, newest))

    document = render_handoff(handoff_repo).decode("utf-8")

    assert "Active handoff: `fixture-versioned-handoff`" in document
    assert f"State: {handoff_module.RECOVERY_HANDOFF_STATE}" in document
    assert "This explicit list is non-exhaustive." in document
    assert "`iter001-acquisition-contract` remains blocked." in document
    assert "This handoff grants no authority." in document

    substituted = newest.model_copy(
        update={
            "links": {
                **newest.links,
                "engine_boundary": "iter001-public-substrate-verdict-v1",
            }
        }
    )
    _install_verified_dependencies(monkeypatch, (*memory_records, checkpoint, substituted))
    with pytest.raises(HandoffError, match="lacks the versioned handoff contract"):
        render_handoff(handoff_repo)

    later = memory_records[59].model_copy(
        update={
            "sequence": newest.sequence + 1,
            "event_id": "fixture-later-state-event",
        }
    )
    _install_verified_dependencies(monkeypatch, (*memory_records, checkpoint, newest, later))
    with pytest.raises(HandoffError, match="must be the final research-memory event"):
        render_handoff(handoff_repo)


@pytest.mark.parametrize(
    ("target", "field"),
    [
        ("checkpoint", "action"),
        ("checkpoint", "outcome"),
        ("checkpoint", "authority_effect"),
        ("handoff", "state"),
        ("handoff", "next_action"),
    ],
)
def test_versioned_recovery_rejects_contradictory_canonical_text(
    target: str,
    field: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint, handoff = _versioned_recovery_records(memory_records)
    selected = checkpoint if target == "checkpoint" else handoff
    changed = selected.model_copy(
        update={"payload": {**selected.payload, field: "Authority is now active."}}
    )
    if target == "checkpoint":
        checkpoint = changed
        handoff = handoff.model_copy(
            update={"links": {**handoff.links, "checkpoint": changed.event_id}}
        )
    else:
        handoff = changed
    _install_verified_dependencies(monkeypatch, (*memory_records, checkpoint, handoff))

    with pytest.raises(HandoffError, match="lacks the versioned handoff contract"):
        render_handoff(handoff_repo)


@pytest.mark.parametrize(
    "report",
    [
        _mission_report(extra_failures=("unexpected-check",)),
        _mission_report(omit_expected=True),
    ],
)
def test_render_rejects_mission_blocker_drift(
    report: MissionValidation,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records, report=report)

    with pytest.raises(HandoffError, match="current mission blockers differ"):
        render_handoff(handoff_repo)


def test_render_rejects_expected_blocker_with_different_failure_cause(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _mission_report()
    checks = tuple(
        check.model_copy(update={"detail": "different acquisition defect"})
        if check.check_id == "iter001-acquisition-contract"
        else check
        for check in report.checks
    )
    _install_verified_dependencies(
        monkeypatch,
        memory_records,
        report=MissionValidation(passed=False, checks=checks),
    )

    with pytest.raises(HandoffError, match="unexpected failure cause"):
        render_handoff(handoff_repo)


def test_render_rejects_checkpoint_that_changes_bootstrap_blocker_policy(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint, _handoff = _selected_recovery_records(memory_records)
    validation = {**checkpoint.payload["validation"], "expected_blockers": ["different-blocker"]}
    payload = {**checkpoint.payload, "validation": validation}
    records = _replace_record(memory_records, checkpoint.event_id, payload=payload)
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(HandoffError, match="blocker policy differs"):
        render_handoff(handoff_repo)


def test_render_rejects_schema_drift(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(
        monkeypatch,
        memory_records,
        schema_errors=["stale schema: protocol/schemas/example.schema.json"],
    )

    with pytest.raises(HandoffError, match="committed schema is stale"):
        render_handoff(handoff_repo)


def test_render_rejects_schema_inventory_drift(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    (handoff_repo / "protocol" / "schemas" / "unexpected.schema.json").write_text(
        "{}\n",
        encoding="utf-8",
    )

    with pytest.raises(HandoffError, match="schema inventory differs"):
        render_handoff(handoff_repo)


def test_render_rejects_duplicate_source_object_keys(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    (handoff_repo / "mission" / "name.json").write_text(
        '{"canonical_slug":"inbar","canonical_slug":"inbar","status":"pending"}\n',
        encoding="utf-8",
    )

    with pytest.raises(HandoffError, match="duplicate object keys"):
        render_handoff(handoff_repo)


def test_render_rejects_nonfinite_source_json(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    (handoff_repo / "mission" / "name.json").write_text(
        '{"canonical_slug":"inbar","score":NaN,"status":"pending"}\n',
        encoding="utf-8",
    )

    with pytest.raises(HandoffError, match="nonfinite JSON"):
        render_handoff(handoff_repo)

    (handoff_repo / "mission" / "name.json").write_text(
        '{"canonical_slug":"inbar","score":1e999,"status":"pending"}\n',
        encoding="utf-8",
    )
    with pytest.raises(HandoffError, match="nonfinite JSON"):
        render_handoff(handoff_repo)


def test_render_escapes_memory_text_before_markdown_emission(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy_records = _legacy_recovery_memory(memory_records)
    handoff = next(
        record for record in legacy_records if record.event_id == _LEGACY_HANDOFF_EVENT_ID
    )
    records = _replace_record(
        legacy_records,
        handoff.event_id,
        payload={**handoff.payload, "next_action": "<!-- hide authority --> # forged"},
    )
    _install_verified_dependencies(monkeypatch, records)

    document = render_handoff(handoff_repo).decode("utf-8")

    assert "<!--" not in document
    assert "&lt;!-- hide authority --&gt; \\# forged" in document


@pytest.mark.parametrize("character", ["\u0085", "\u2028", "\u2029", "\u202e"])
def test_render_rejects_unicode_line_and_direction_controls(
    character: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy_records = _legacy_recovery_memory(memory_records)
    handoff = next(
        record for record in legacy_records if record.event_id == _LEGACY_HANDOFF_EVENT_ID
    )
    records = _replace_record(
        legacy_records,
        handoff.event_id,
        payload={**handoff.payload, "next_action": f"trusted{character}forged"},
    )
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(HandoffError, match="control character"):
        render_handoff(handoff_repo)


def test_render_rejects_unicode_controls_in_source_contracts(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    name_path = handoff_repo / "mission" / "name.json"
    value = json.loads(name_path.read_text(encoding="utf-8"))
    value["status"] = "pending\u202eapproved"
    name_path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(HandoffError, match="control character"):
        render_handoff(handoff_repo)


def test_handoff_snapshots_reject_hard_link_aliases(
    handoff_repo: Path,
    tmp_path: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    contract = handoff_repo / "mission" / "contract.json"
    (tmp_path / "contract-alias.json").hardlink_to(contract)

    with pytest.raises(HandoffError, match="must not be hard linked"):
        render_handoff(handoff_repo)


def test_check_rejects_a_hard_linked_handoff(
    handoff_repo: Path,
    tmp_path: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    path = write_handoff(handoff_repo)
    (tmp_path / "handoff-alias.md").hardlink_to(path)

    with pytest.raises(HandoffError, match="must not be hard linked"):
        check_handoff(handoff_repo)


def test_write_handoff_rejects_input_change_between_render_and_write(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    original_write = handoff_module.atomic_write

    def changing_write(path: Path, content: bytes) -> None:
        original_write(path, content)
        contract_path = handoff_repo / "mission" / "contract.json"
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        contract["source_digest_fixture"] = "changed-after-render"
        contract_path.write_text(
            json.dumps(contract, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    monkeypatch.setattr(handoff_module, "atomic_write", changing_write)

    with pytest.raises(HandoffError, match=r"HANDOFF\.md is stale"):
        write_handoff(handoff_repo)


@pytest.mark.parametrize("mode", ["aggregate", "duplicate", "substitution"])
def test_render_binds_the_complete_mission_report_contract(
    mode: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _mission_report()
    if mode == "aggregate":
        report = report.model_copy(update={"passed": True})
        message = "aggregate is internally inconsistent"
    else:
        checks = list(report.checks)
        replacement = checks[-2].model_copy(
            update={"check_id": checks[-1].check_id if mode == "duplicate" else "substituted-check"}
        )
        checks[-2] = replacement
        report = MissionValidation(passed=False, checks=tuple(checks))
        message = "duplicate check IDs" if mode == "duplicate" else "check inventory differs"
    _install_verified_dependencies(monkeypatch, memory_records, report=report)

    with pytest.raises(HandoffError, match=message):
        render_handoff(handoff_repo)


@pytest.mark.parametrize("target", ["checkpoint", "handoff"])
def test_render_requires_commit_bound_recovery_evidence(
    target: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint, handoff = _selected_recovery_records(memory_records)
    event_id = checkpoint.event_id if target == "checkpoint" else handoff.event_id
    records = _replace_record(memory_records, event_id, evidence=())
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(HandoffError, match="lacks required Git-anchored evidence roles"):
        render_handoff(handoff_repo)


@pytest.mark.parametrize(
    "changed_label",
    [
        "mission/contract.json",
        "memory/research_engine_extraction.jsonl",
        "schema alpha.schema.json",
    ],
)
def test_render_rejects_input_change_during_snapshot(
    changed_label: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    original_read = handoff_module._read_regular_file
    reads = 0

    def changing_read(repo_root: Path, relative: str, label: str) -> bytes:
        nonlocal reads
        data = original_read(repo_root, relative, label)
        if label == changed_label:
            reads += 1
            if reads == 2:
                return data[:-1] + bytes([data[-1] ^ 1])
        return data

    monkeypatch.setattr(handoff_module, "_read_regular_file", changing_read)

    with pytest.raises(HandoffError, match=r"changed during .*rendering"):
        render_handoff(handoff_repo)


def test_render_rejects_mission_state_change_during_rendering(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _mission_report()
    _install_verified_dependencies(monkeypatch, memory_records, report=report)
    changed_checks = tuple(
        check.model_copy(update={"detail": "changed during rendering"})
        if check.check_id == "owner-boundary"
        else check
        for check in report.checks
    )
    reports = iter(
        (
            report,
            MissionValidation(passed=False, checks=changed_checks),
        )
    )
    monkeypatch.setattr(handoff_module, "validate_mission", lambda _repo: next(reports))

    with pytest.raises(HandoffError, match="mission validation changed during handoff rendering"):
        render_handoff(handoff_repo)


def test_render_rechecks_source_after_unchanged_final_mission_validation(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _mission_report()
    _install_verified_dependencies(monkeypatch, memory_records, report=report)
    calls = 0

    def changing_validation(_repo: Path) -> MissionValidation:
        nonlocal calls
        calls += 1
        if calls == 2:
            contract_path = handoff_repo / "mission" / "contract.json"
            contract_path.write_bytes(contract_path.read_bytes() + b" ")
        return report

    monkeypatch.setattr(handoff_module, "validate_mission", changing_validation)

    with pytest.raises(
        HandoffError,
        match=r"handoff source changed during rendering: mission/contract\.json",
    ):
        render_handoff(handoff_repo)


def test_render_rejects_recovery_input_aba_change_with_restored_bytes(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _mission_report()
    _install_verified_dependencies(monkeypatch, memory_records, report=report)
    claim_path = handoff_repo / "claims" / "registry.jsonl"
    original = claim_path.read_bytes()
    calls = 0

    def changing_validation(_repo: Path) -> MissionValidation:
        nonlocal calls
        calls += 1
        if calls == 2:
            replacement = claim_path.with_suffix(".replacement")
            replacement.write_bytes(b'{"claim":"temporarily-active"}\n')
            replacement.replace(claim_path)
            claim_path.write_bytes(original)
        return report

    monkeypatch.setattr(handoff_module, "validate_mission", changing_validation)

    with pytest.raises(HandoffError, match="recovery input manifest changed"):
        render_handoff(handoff_repo)


@pytest.mark.parametrize("mode", ["checkpoint", "handoff"])
def test_render_rejects_duplicate_checkpoint_and_handoff_lists(
    mode: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint, handoff = _selected_recovery_records(memory_records)
    record = checkpoint if mode == "checkpoint" else handoff
    if mode == "checkpoint":
        validation = {
            **record.payload["validation"],
            "expected_blockers": [
                "iter001-acquisition-contract",
                "iter001-acquisition-contract",
            ],
        }
        payload_update: dict[str, object] = {"validation": validation}
    else:
        payload_update = {"remaining_gates": ["duplicate gate", "duplicate gate"]}
    records = _replace_record(
        memory_records,
        record.event_id,
        payload={**record.payload, **payload_update},
    )
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(HandoffError, match="payload violates its exact contract"):
        render_handoff(handoff_repo)


@pytest.mark.parametrize("mode", ["absent", "not-blocked"])
def test_render_requires_a_blocked_inbar_handoff(
    mode: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _checkpoint, handoff = _selected_recovery_records(memory_records)
    if mode == "absent":
        records = tuple(
            record
            for record in memory_records
            if record.event_type != handoff_module.MemoryEventType.HANDOFF
        )
    else:
        records = _replace_record(memory_records, handoff.event_id, status=MemoryStatus.PASS)
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(HandoffError, match=r"no Inbar handoff|preserve blocked"):
        render_handoff(handoff_repo)


@pytest.mark.parametrize("mode", ["invalid", "empty"])
def test_render_rejects_invalid_or_empty_memory_snapshot(
    mode: str,
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(handoff_module, "validate_mission", lambda _repo: _mission_report())
    if mode == "invalid":
        monkeypatch.setattr(
            handoff_module,
            "load_memory_records_bytes",
            lambda _data: (_ for _ in ()).throw(ValueError("invalid")),
        )
    else:
        monkeypatch.setattr(handoff_module, "load_memory_records_bytes", lambda _data: ())

    with pytest.raises(HandoffError, match=r"research memory is invalid|research memory is empty"):
        render_handoff(handoff_repo)


@pytest.mark.parametrize("target", ["source", "engine"])
def test_render_requires_frozen_source_and_engine_events(
    target: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_id = (
        "iter001-public-substrate-verdict-v1"
        if target == "source"
        else "future-research-engine-shortcut-v2-lessons-v1"
    )
    records = tuple(record for record in memory_records if record.event_id != event_id)
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(HandoffError, match="required research-memory event is invalid"):
        render_handoff(handoff_repo)


@pytest.mark.parametrize("target", ["checkpoint", "handoff"])
def test_render_rejects_checkpoint_commit_substitution(
    target: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint, handoff = _selected_recovery_records(memory_records)
    event_id = checkpoint.event_id if target == "checkpoint" else handoff.event_id
    records = _replace_record(memory_records, event_id, source_commit="f" * 40)
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(HandoffError, match="source commit differs"):
        render_handoff(handoff_repo)


@pytest.mark.parametrize("mode", ["unexpected", "policy", "count"])
def test_render_rejects_checkpoint_validation_policy_drift(
    mode: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint, _handoff = _selected_recovery_records(memory_records)
    validation = dict(checkpoint.payload["validation"])
    if mode == "unexpected":
        validation["unexpected_blockers"] = ["unexpected-check"]
    elif mode == "policy":
        validation["expected_blockers"] = []
    else:
        validation["mission_checks"] = 23
    records = _replace_record(
        memory_records,
        checkpoint.event_id,
        payload={**checkpoint.payload, "validation": validation},
    )
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(
        HandoffError,
        match=r"unexpected mission blockers|blocker policy differs|check count differs",
    ):
        render_handoff(handoff_repo)


@pytest.mark.parametrize("mode", ["identity", "publication", "authority"])
def test_render_rejects_identity_and_authority_state_drift(
    mode: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    if mode == "identity":
        path = handoff_repo / "mission" / "name.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["canonical_slug"] = "fieldtrue"
    elif mode == "publication":
        path = handoff_repo / "mission" / "loop.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["publication_transition"] = {"status": "published"}
    else:
        path = handoff_repo / "protocol" / "acquisition" / "iter001_contract.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["control_authority_status"] = "sealed"
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(HandoffError, match=r"identity contracts disagree|cannot imply activated"):
        render_handoff(handoff_repo)


def test_render_rejects_schema_inventory_and_directory_race(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    extra = handoff_repo / "protocol" / "schemas" / "extra.schema.json"
    extra.write_text("{}\n", encoding="utf-8")
    with pytest.raises(HandoffError, match="schema inventory differs"):
        render_handoff(handoff_repo)
    extra.unlink()

    original_snapshot = handoff_module._directory_snapshot
    calls = 0

    def changed_snapshot(
        repo_root: Path, relative: str, label: str
    ) -> tuple[tuple[str, ...], tuple[int, ...]]:
        nonlocal calls
        snapshot = original_snapshot(repo_root, relative, label)
        calls += 1
        if calls == 2:
            return snapshot[0], (*snapshot[1][:-1], snapshot[1][-1] + 1)
        return snapshot

    monkeypatch.setattr(handoff_module, "_directory_snapshot", changed_snapshot)
    with pytest.raises(HandoffError, match="schema directory changed"):
        render_handoff(handoff_repo)


def test_low_level_handoff_snapshot_guards(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(HandoffError, match="unsafe repository path"):
        handoff_module._read_regular_file(handoff_repo, "../escape", "fixture")
    with pytest.raises(HandoffError, match="unsafe repository path"):
        handoff_module._directory_snapshot(handoff_repo, "/escape", "fixture")
    with pytest.raises(HandoffError, match="must be a regular file"):
        handoff_module._read_regular_file(handoff_repo, "mission", "fixture")
    monkeypatch.setattr(handoff_module, "_MAX_INPUT_BYTES", 4)
    with pytest.raises(HandoffError, match="exceeds the handoff input limit"):
        handoff_module._read_regular_file(
            handoff_repo,
            "mission/contract.json",
            "fixture",
        )


@pytest.mark.parametrize(
    ("limit_name", "message"),
    [
        ("_MAX_RECOVERY_INPUT_DIRECTORIES", "directory count exceeds"),
        ("_MAX_RECOVERY_INPUT_ENTRIES", "entry count exceeds"),
    ],
)
def test_recovery_manifest_bounds_directory_inventory(
    limit_name: str,
    message: str,
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(handoff_module, limit_name, 0)

    with pytest.raises(HandoffError, match=message):
        handoff_module._recovery_manifest(handoff_repo)


@pytest.mark.parametrize("payload", [b"[1,2,3]\n", b"not json\n"])
def test_render_rejects_nonobject_or_invalid_json_source(
    payload: bytes,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    (handoff_repo / "mission" / "name.json").write_bytes(payload)
    with pytest.raises(HandoffError, match=r"must be a JSON object|not valid UTF-8 JSON"):
        render_handoff(handoff_repo)


def test_render_wraps_unexpected_input_errors(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        handoff_module,
        "_render",
        lambda _repo: (_ for _ in ()).throw(OSError("fixture")),
    )
    with pytest.raises(HandoffError, match="inputs could not be verified"):
        render_handoff(handoff_repo)


def test_render_rejects_nonfinite_json_source_value(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    contract_path = handoff_repo / "mission" / "contract.json"
    contract_path.write_bytes(contract_path.read_bytes().replace(b'"one"', b"NaN"))

    with pytest.raises(HandoffError, match="contains nonfinite JSON value"):
        render_handoff(handoff_repo)


def test_import_guard_rejects_unbound_fieldtrue_module_directly() -> None:
    guard = handoff_module._RejectUnboundFieldtrueImports()

    assert guard.find_spec("fieldtrue.handoff", None) is None
    with pytest.raises(HandoffError, match="unbound Fieldtrue module import"):
        guard.find_spec("fieldtrue.adversarial_fixture", None)


@pytest.mark.parametrize(
    ("mode", "message"),
    [
        ("not-module", "has no module object"),
        ("no-loader", "has no source-code loader"),
        ("outside-root", "outside the source root"),
        ("not-source", "is not Python source"),
        ("no-code", "has no executable module code"),
    ],
)
def test_capture_bound_module_closure_rejects_malformed_population(
    mode: str,
    message: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    name = "fieldtrue.000_adversarial_capture"
    if mode == "not-module":
        monkeypatch.setitem(sys.modules, name, object())
    else:
        module = ModuleType(name)
        if mode == "no-loader":
            module.__file__ = str(Path(handoff_module.__file__).resolve(strict=True))
        else:
            source = tmp_path / "capture.py"
            source.write_text("VALUE = 1\n", encoding="utf-8")
            if mode in {"not-source", "no-code"}:
                source_root = Path(handoff_module.__file__).resolve(strict=True).parents[1]
                source = (
                    source_root / "fieldtrue" / "py.typed"
                    if mode == "not-source"
                    else source_root / "fieldtrue" / "__init__.py"
                )

            class Loader:
                def get_code(self, fullname: str) -> object:
                    del fullname
                    if mode == "no-code":
                        return None
                    return compile(source.read_text(encoding="utf-8"), str(source), "exec")

            module.__file__ = str(source)
            module.__spec__ = type("FixtureSpec", (), {"loader": Loader()})()
        monkeypatch.setitem(sys.modules, name, module)

    with pytest.raises(RuntimeError, match=message):
        handoff_module._capture_bound_fieldtrue_modules()


def test_capture_bound_module_closure_requires_authority_members(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "modules", {})
    with pytest.raises(RuntimeError, match="authority module closure could not be captured"):
        handoff_module._capture_bound_fieldtrue_modules()


def test_capture_bound_module_closure_requires_lazy_authority_modules(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "modules", {handoff_module.__name__: handoff_module})
    with pytest.raises(RuntimeError, match="lazy mission authority modules were not captured"):
        handoff_module._capture_bound_fieldtrue_modules()


@pytest.mark.parametrize("mode", ["unexpected-duplicate", "overlap", "mission-duplicate"])
def test_checkpoint_validation_rejects_ambiguous_blocker_and_check_sets(
    mode: str,
    memory_records: tuple[ResearchMemoryRecord, ...],
) -> None:
    checkpoint, _handoff = _selected_recovery_records(memory_records)
    validation = dict(checkpoint.payload["validation"])
    if mode == "unexpected-duplicate":
        validation["unexpected_blockers"] = ["other-blocker", "other-blocker"]
    elif mode == "overlap":
        validation["unexpected_blockers"] = ["iter001-acquisition-contract"]
    else:
        validation["mission_check_ids"] = ["owner-boundary", "owner-boundary"]

    with pytest.raises(ValueError, match=r"unexpected blockers|disjoint|check IDs"):
        handoff_module._CheckpointValidation.model_validate(validation)


def test_handoff_validation_rejects_noncanonical_remaining_gate_set(
    memory_records: tuple[ResearchMemoryRecord, ...],
) -> None:
    _checkpoint, handoff = _selected_recovery_records(memory_records)

    with pytest.raises(ValueError, match="remaining gates differ"):
        handoff_module._HandoffPayload.model_validate(
            {**handoff.payload, "remaining_gates": ["noncanonical gate"]}
        )


def test_snapshot_flags_fail_closed_without_no_follow_support(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delattr(handoff_module.os, "O_DIRECTORY")
    with pytest.raises(HandoffError, match="directory no-follow support"):
        handoff_module._directory_flags()

    monkeypatch.undo()
    monkeypatch.delattr(handoff_module.os, "O_NOFOLLOW")
    with pytest.raises(HandoffError, match="file no-follow support"):
        handoff_module._file_flags()


def test_bounded_directory_names_wraps_enumeration_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_scandir(_descriptor: int) -> object:
        raise OSError("fixture enumeration failure")

    monkeypatch.setattr(handoff_module.os, "scandir", fail_scandir)
    with pytest.raises(HandoffError, match="cannot be enumerated"):
        handoff_module._bounded_directory_names(0, 1, "fixture directory")


@pytest.mark.parametrize("root_failure", [False, True])
def test_directory_snapshot_rejects_unavailable_components(
    root_failure: bool,
    handoff_repo: Path,
    tmp_path: Path,
) -> None:
    root = tmp_path / "absent-root" if root_failure else handoff_repo
    relative = "mission" if root_failure else "mission/absent"

    with pytest.raises(HandoffError, match="unavailable or traverses a symbolic link"):
        handoff_module._directory_snapshot(root, relative, "fixture directory")


def test_directory_snapshot_wraps_descriptor_enumeration_error(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        handoff_module,
        "_bounded_directory_names",
        lambda *_args: (_ for _ in ()).throw(OSError("fixture")),
    )

    with pytest.raises(HandoffError, match="cannot be enumerated"):
        handoff_module._directory_snapshot(handoff_repo, "mission", "fixture directory")


def test_directory_snapshot_rejects_metadata_change_during_enumeration(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def changing_fields(_metadata: object) -> tuple[int, ...]:
        nonlocal calls
        calls += 1
        return (calls,)

    monkeypatch.setattr(handoff_module, "_stable_stat_fields", changing_fields)

    with pytest.raises(HandoffError, match="changed while being enumerated"):
        handoff_module._directory_snapshot(handoff_repo, "mission", "fixture directory")


def test_file_snapshot_rejects_unavailable_root(tmp_path: Path) -> None:
    with pytest.raises(HandoffError, match="is unavailable"):
        handoff_module._read_regular_file(tmp_path / "absent", "README.md", "fixture file")


def test_file_snapshot_wraps_descriptor_read_failure(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        handoff_module.os,
        "fstat",
        lambda _descriptor: (_ for _ in ()).throw(OSError("fixture")),
    )

    with pytest.raises(HandoffError, match="cannot be read"):
        handoff_module._read_regular_file(handoff_repo, "README.md", "fixture file")


def test_file_snapshot_rejects_metadata_change_while_reading(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def changing_fields(_metadata: object) -> tuple[int, ...]:
        nonlocal calls
        calls += 1
        return (calls,)

    monkeypatch.setattr(handoff_module, "_stable_stat_fields", changing_fields)

    with pytest.raises(HandoffError, match="changed while being read"):
        handoff_module._read_regular_file(handoff_repo, "README.md", "fixture file")


def test_recovery_exclusion_policy_covers_root_and_cache_boundaries() -> None:
    assert not handoff_module._is_recovery_excluded(Path("."), directory=True)
    assert handoff_module._is_recovery_excluded(Path(".git"), directory=True)
    assert handoff_module._is_recovery_excluded(Path("nested/__pycache__"), directory=True)


def test_manifest_file_rejects_missing_changed_nonregular_and_oversize_inputs(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor = handoff_module.os.open(handoff_repo, handoff_module._directory_flags())
    try:
        initial = handoff_module.os.stat("README.md", dir_fd=descriptor, follow_symlinks=False)
        with pytest.raises(HandoffError, match="is unavailable"):
            handoff_module._read_manifest_file(
                descriptor,
                "absent.txt",
                Path("absent.txt"),
                initial,
            )
        with pytest.raises(HandoffError, match="changed before reading"):
            handoff_module._read_manifest_file(
                descriptor,
                "README.md",
                Path("README.md"),
                handoff_module.os.stat("mission", dir_fd=descriptor, follow_symlinks=False),
            )
        with pytest.raises(HandoffError, match="must be a regular file"):
            handoff_module._read_manifest_file(
                descriptor,
                "mission",
                Path("mission"),
                handoff_module.os.stat("mission", dir_fd=descriptor, follow_symlinks=False),
            )
        monkeypatch.setattr(handoff_module, "_MAX_INPUT_BYTES", 0)
        with pytest.raises(HandoffError, match="exceeds the per-file limit"):
            handoff_module._read_manifest_file(
                descriptor,
                "README.md",
                Path("README.md"),
                initial,
            )
    finally:
        handoff_module.os.close(descriptor)


def test_manifest_file_wraps_read_error(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor = handoff_module.os.open(handoff_repo, handoff_module._directory_flags())
    initial = handoff_module.os.stat("README.md", dir_fd=descriptor, follow_symlinks=False)
    monkeypatch.setattr(
        handoff_module.os,
        "fdopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("fixture")),
    )
    try:
        with pytest.raises(HandoffError, match="cannot be read"):
            handoff_module._read_manifest_file(
                descriptor,
                "README.md",
                Path("README.md"),
                initial,
            )
    finally:
        handoff_module.os.close(descriptor)


def test_manifest_file_rejects_metadata_change_while_reading(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor = handoff_module.os.open(handoff_repo, handoff_module._directory_flags())
    initial = handoff_module.os.stat("README.md", dir_fd=descriptor, follow_symlinks=False)
    calls = 0

    def changing_fields(_metadata: object) -> tuple[int, ...]:
        nonlocal calls
        calls += 1
        return (1,) if calls <= 2 else (calls,)

    monkeypatch.setattr(handoff_module, "_stable_stat_fields", changing_fields)
    try:
        with pytest.raises(HandoffError, match="changed while being read"):
            handoff_module._read_manifest_file(
                descriptor,
                "README.md",
                Path("README.md"),
                initial,
            )
    finally:
        handoff_module.os.close(descriptor)


def test_recovery_manifest_rejects_excess_depth(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(handoff_module, "_MAX_RECOVERY_INPUT_DEPTH", 0)

    with pytest.raises(HandoffError, match="depth exceeds"):
        handoff_module._recovery_manifest(handoff_repo)


def test_recovery_manifest_wraps_initial_enumeration_oserror(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        handoff_module,
        "_bounded_directory_names",
        lambda *_args: (_ for _ in ()).throw(OSError("fixture")),
    )

    with pytest.raises(HandoffError, match="recovery directory cannot be enumerated"):
        handoff_module._recovery_manifest(handoff_repo)


def test_recovery_manifest_requires_directory_root_metadata(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    file_metadata = handoff_module.os.stat(handoff_repo / "README.md")
    monkeypatch.setattr(handoff_module.os, "fstat", lambda _descriptor: file_metadata)
    monkeypatch.setattr(handoff_module, "_bounded_directory_names", lambda *_args: ())

    with pytest.raises(HandoffError, match="root must be a directory"):
        handoff_module._recovery_manifest(handoff_repo)


def test_recovery_manifest_wraps_child_inspection_failure(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        handoff_module.os,
        "stat",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("fixture")),
    )

    with pytest.raises(HandoffError, match="recovery input cannot be inspected"):
        handoff_module._recovery_manifest(handoff_repo)


def test_recovery_manifest_rejects_directory_open_failure(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_open = handoff_module.os.open

    def fail_child_directory(
        path: object,
        flags: int,
        *args: object,
        **kwargs: object,
    ) -> int:
        if path == ".github":
            raise OSError("fixture")
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(handoff_module.os, "open", fail_child_directory)

    with pytest.raises(HandoffError, match="recovery directory traverses a symbolic link"):
        handoff_module._recovery_manifest(handoff_repo)


def test_recovery_manifest_rejects_directory_change_before_traversal(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_open = handoff_module.os.open

    def change_after_open(
        path: object,
        flags: int,
        *args: object,
        **kwargs: object,
    ) -> int:
        descriptor = original_open(path, flags, *args, **kwargs)
        if path == ".github":
            (handoff_repo / ".github" / "post-open-race.txt").write_text(
                "changed\n", encoding="utf-8"
            )
        return descriptor

    monkeypatch.setattr(handoff_module.os, "open", change_after_open)

    with pytest.raises(HandoffError, match="changed before traversal"):
        handoff_module._recovery_manifest(handoff_repo)


def test_recovery_manifest_rejects_directory_change_after_traversal(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_stat = handoff_module.os.stat
    root_descriptor: int | None = None
    observations = 0

    def changing_stat(
        path: object,
        *args: object,
        **kwargs: object,
    ) -> object:
        nonlocal observations, root_descriptor
        directory_descriptor = kwargs.get("dir_fd")
        if path == ".github":
            if root_descriptor is None:
                root_descriptor = int(directory_descriptor)
            if directory_descriptor == root_descriptor:
                observations += 1
                if observations == 2:
                    (handoff_repo / ".github" / "post-traversal-race.txt").write_text(
                        "changed\n", encoding="utf-8"
                    )
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(handoff_module.os, "stat", changing_stat)

    with pytest.raises(HandoffError, match=r"changed during traversal: \.github"):
        handoff_module._recovery_manifest(handoff_repo)


@pytest.mark.parametrize(
    ("limit_name", "message"),
    [
        ("_MAX_RECOVERY_INPUT_FILES", "file count exceeds"),
        ("_MAX_RECOVERY_INPUT_BYTES", "bytes exceed"),
    ],
)
def test_recovery_manifest_rejects_file_and_byte_limit_overflow(
    limit_name: str,
    message: str,
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(handoff_module, limit_name, 0)

    with pytest.raises(HandoffError, match=message):
        handoff_module._recovery_manifest(handoff_repo)


def test_recovery_manifest_rejects_special_file(
    handoff_repo: Path,
) -> None:
    handoff_module.os.mkfifo(handoff_repo / "adversarial.pipe")

    with pytest.raises(HandoffError, match="regular file or directory"):
        handoff_module._recovery_manifest(handoff_repo)


def test_recovery_manifest_wraps_resnapshot_oserror(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "empty-recovery-root"
    root.mkdir()
    calls = 0

    def fail_resnapshot(*_args: object) -> tuple[str, ...]:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("fixture")
        return ()

    monkeypatch.setattr(handoff_module, "_bounded_directory_names", fail_resnapshot)

    with pytest.raises(HandoffError, match="cannot be resnapshotted"):
        handoff_module._recovery_manifest(root)


def test_recovery_manifest_rejects_changed_root_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "empty-recovery-root"
    root.mkdir()
    calls = 0

    def change_resnapshot(*_args: object) -> tuple[str, ...]:
        nonlocal calls
        calls += 1
        return () if calls == 1 else ("appeared",)

    monkeypatch.setattr(handoff_module, "_bounded_directory_names", change_resnapshot)

    with pytest.raises(HandoffError, match=r"changed during traversal: \."):
        handoff_module._recovery_manifest(root)


def test_recovery_manifest_rejects_unavailable_root(tmp_path: Path) -> None:
    with pytest.raises(HandoffError, match="root is unavailable"):
        handoff_module._recovery_manifest(tmp_path / "absent-root")


def test_bound_module_verification_rejects_identity_substitution(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = handoff_module._BOUND_FIELDTRUE_MODULES[0]
    monkeypatch.setitem(sys.modules, binding.name, ModuleType(binding.name))

    with pytest.raises(HandoffError, match="bound Fieldtrue module identity changed"):
        handoff_module._verify_bound_module_sources(handoff_repo)


def test_bound_module_verification_wraps_compile_failure(
    handoff_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_compile(*_args: object, **_kwargs: object) -> object:
        raise SyntaxError("fixture")

    monkeypatch.setattr(handoff_module, "compile", fail_compile, raising=False)

    with pytest.raises(HandoffError, match="source cannot be compiled"):
        handoff_module._verify_bound_module_sources(handoff_repo)


def test_module_population_rejects_bound_identity_substitution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = handoff_module._BOUND_FIELDTRUE_MODULES[0]
    initial_names = handoff_module._loaded_fieldtrue_module_names()
    monkeypatch.setitem(sys.modules, binding.name, ModuleType(binding.name))

    with pytest.raises(HandoffError, match="bound Fieldtrue module identity changed"):
        handoff_module._verify_module_population(initial_names)


def test_json_and_required_string_accept_finite_scalar_and_reject_empty_value() -> None:
    assert handoff_module._finite_json_float("1.25", "fixture") == 1.25
    with pytest.raises(HandoffError, match="must be a nonempty string"):
        handoff_module._required_string({"field": ""}, "field", "fixture")


def test_render_rejects_unbound_recovery_evidence_uri(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint, _handoff = _selected_recovery_records(memory_records)
    evidence = tuple(
        item.model_copy(update={"uri": "https://example.invalid/substitution"})
        if index == 0
        else item
        for index, item in enumerate(checkpoint.evidence)
    )
    records = _replace_record(memory_records, checkpoint.event_id, evidence=evidence)
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(HandoffError, match="not commit and byte bound"):
        render_handoff(handoff_repo)


def test_render_rejects_recovery_memory_identity_drift(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint, _handoff = _selected_recovery_records(memory_records)
    records = _replace_record(memory_records, checkpoint.event_id, mission_id="different-mission")
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(HandoffError, match="current Inbar memory identity"):
        render_handoff(handoff_repo)


def test_render_accepts_frozen_legacy_recovery_contract(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy_records = _legacy_recovery_memory(memory_records)
    _install_verified_dependencies(monkeypatch, legacy_records)

    document = render_handoff(handoff_repo).decode("utf-8")

    assert f"Active handoff: `{_LEGACY_HANDOFF_EVENT_ID}`" in document
    assert f"Checkpoint event: `{_LEGACY_CHECKPOINT_EVENT_ID}`" in document
    assert "This frozen legacy list is non-exhaustive." in document


def test_render_rejects_legacy_recovery_contract_drift(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy_records = _legacy_recovery_memory(memory_records)
    records = _replace_record(legacy_records, _LEGACY_CHECKPOINT_EVENT_ID, stage="mission-handoff")
    _install_verified_dependencies(monkeypatch, records)

    with pytest.raises(HandoffError, match="legacy recovery pair differs"):
        render_handoff(handoff_repo)


@pytest.mark.parametrize("mode", ["missing", "mismatch"])
def test_render_rejects_unavailable_or_mismatched_imported_renderer_bytes(
    mode: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    imported = None if mode == "missing" else b"different imported renderer"
    monkeypatch.setattr(handoff_module, "_IMPORTED_RENDERER_BYTES", imported)

    with pytest.raises(
        HandoffError,
        match=r"source bytes are unavailable|source differs from repository source",
    ):
        render_handoff(handoff_repo)


@pytest.mark.parametrize("mode", ["compile-error", "code-mismatch"])
def test_render_rejects_final_renderer_compilation_substitution(
    mode: str,
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    original_compile = compile
    calls = 0
    bound_compilations = len(handoff_module._BOUND_FIELDTRUE_MODULES)

    def substituted_compile(
        source: object,
        filename: str,
        compile_mode: str,
        *args: object,
        **kwargs: object,
    ) -> object:
        nonlocal calls
        calls += 1
        if calls <= bound_compilations:
            return original_compile(source, filename, compile_mode, *args, **kwargs)
        if mode == "compile-error":
            raise SyntaxError("fixture")
        return original_compile("VALUE = 1\n", filename, compile_mode, *args, **kwargs)

    monkeypatch.setattr(handoff_module, "compile", substituted_compile, raising=False)

    with pytest.raises(
        HandoffError,
        match=r"renderer source cannot be compiled|renderer code differs",
    ):
        render_handoff(handoff_repo)


def test_versioned_render_rejects_mission_check_id_drift(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint, handoff = _versioned_recovery_records(memory_records)
    validation = {
        **checkpoint.payload["validation"],
        "mission_check_ids": [
            *handoff_module._EXPECTED_MISSION_CHECK_IDS[:-1],
            "substituted-provider-check",
        ],
    }
    checkpoint = checkpoint.model_copy(
        update={"payload": {**checkpoint.payload, "validation": validation}}
    )
    _install_verified_dependencies(monkeypatch, (*memory_records, checkpoint, handoff))

    with pytest.raises(HandoffError, match="mission check IDs differ"):
        render_handoff(handoff_repo)


def test_render_rejects_nonobject_publication_transition(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    loop_path = handoff_repo / "mission" / "loop.json"
    loop = json.loads(loop_path.read_text(encoding="utf-8"))
    loop["publication_transition"] = "blocked"
    loop_path.write_text(json.dumps(loop, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(HandoffError, match="publication transition must be an object"):
        render_handoff(handoff_repo)


def test_render_rejects_renderer_change_during_final_snapshot(
    handoff_repo: Path,
    memory_records: tuple[ResearchMemoryRecord, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_verified_dependencies(monkeypatch, memory_records)
    original_read = handoff_module._read_regular_file
    renderer_reads = 0

    def changing_read(repo_root: Path, relative: str, label: str) -> bytes:
        nonlocal renderer_reads
        data = original_read(repo_root, relative, label)
        if label == handoff_module._RENDERER_PATH:
            renderer_reads += 1
            if renderer_reads == 2:
                return data + b"# concurrent renderer substitution\n"
        return data

    monkeypatch.setattr(handoff_module, "_read_regular_file", changing_read)

    with pytest.raises(HandoffError, match="renderer changed during rendering"):
        render_handoff(handoff_repo)
