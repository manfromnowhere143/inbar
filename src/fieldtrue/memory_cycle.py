"""Produce the receipt, ledger, and handoff cycle that lands a candidate.

The handoff checker requires an exact topology: a validation-evidence commit that is the
single-parent child of the implementation head, three chained research-memory events bound to
those commits, and a final commit that changes only the ledger and the generated handoff. The
checker was committed; the producer that satisfies it was not — every prior cycle came from
out-of-repo tooling, so a fresh clone could verify a handoff it had no way to make.

This module closes that gap. It runs the committed validation producer, commits the evidence,
appends the resource, checkpoint, and handoff events to the append-only ledger, renders the
handoff from verified machine state, commits the two files, and requires the committed checker
to accept the result before reporting success.

The cycle records engineering observations only. It grants no authority, asserts no scientific
result, and leaves the registered acquisition blocker in force.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from fieldtrue.canonical import sha256_value
from fieldtrue.domain import EngineeringValidationReceipt
from fieldtrue.handoff import (
    RECOVERY_CHECKPOINT_ACTION,
    RECOVERY_CHECKPOINT_AUTHORITY_EFFECT,
    RECOVERY_CHECKPOINT_OUTCOME,
)
from fieldtrue.memory import ResearchMemoryRecord
from fieldtrue.validation_producer import write_validation_receipt

_MEMORY_PATH: Final = "memory/research_engine_extraction.jsonl"
_HANDOFF_PATH: Final = "HANDOFF.md"
_RENDERER_PATH: Final = "src/fieldtrue/handoff.py"
_LEGACY_SOURCE_VERDICT_EVENT: Final = "iter001-public-substrate-verdict-v1"
_ENGINE_BOUNDARY_EVENT: Final = "future-research-engine-shortcut-v2-lessons-v1"
_SOURCE_AUDIT_PATH: Final = "docs/research/ITER001_SOURCE_ROLE_AUDIT.md"


class MemoryCycleError(RuntimeError):
    """The handoff cycle could not be produced or did not verify."""


def _git(repo_root: Path, *args: str) -> str:
    completed = subprocess.run(  # noqa: S603 - fixed trusted Git path, fixed argv
        ["/usr/bin/git", *args],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _run_inbar(repo_root: Path, *args: str) -> str:
    completed = subprocess.run(  # noqa: S603 - fixed committed CLI plan
        ["uv", "run", "inbar", *args],  # noqa: S607 - same PATH resolution as the frozen plan
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise MemoryCycleError(
            f"inbar {' '.join(args)} failed: {completed.stdout.strip()} {completed.stderr.strip()}"
        )
    return completed.stdout


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _evidence_ref(
    repo_root: Path, *, uri: str, git_commit: str, media_type: str, role: str
) -> dict[str, Any]:
    digest = hashlib.sha256((repo_root / uri).read_bytes()).hexdigest()
    return {
        "access": "internal",
        "git_commit": git_commit,
        "label_access": "none",
        "media_type": media_type,
        "role": role,
        "sha256": digest,
        "uri": uri,
    }


def _load_ledger(repo_root: Path) -> list[dict[str, Any]]:
    lines = (repo_root / _MEMORY_PATH).read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines]


def _append_event(
    repo_root: Path,
    *,
    previous: dict[str, Any],
    event_id: str,
    event_type: str,
    stage: str,
    status: str,
    actor_id: str,
    summary: str,
    payload: dict[str, Any],
    evidence: list[dict[str, Any]],
    links: dict[str, str],
    source_commit: str,
) -> dict[str, Any]:
    moment = _now()
    body: dict[str, Any] = {
        "access": "internal",
        "actor": {"actor_id": actor_id, "kind": "agent"},
        "corrects_event_id": None,
        "cost_usd": "0",
        "engine_requirement": None,
        "epistemic_phase": "retrospective",
        "event_id": event_id,
        "event_type": event_type,
        "evidence": evidence,
        "links": links,
        "manual_minutes": 0.0,
        "mission_id": "inbar",
        "occurred_at": moment,
        "payload": payload,
        "previous_event_hash": previous["event_hash"],
        "recorded_at": moment,
        "recurrence_key": None,
        "schema_version": "daniel.research-memory.v2",
        "sequence": previous["sequence"] + 1,
        "source_commit": source_commit,
        "stage": stage,
        "status": status,
        "summary": summary,
    }
    body["event_hash"] = sha256_value({k: v for k, v in body.items() if k != "event_hash"})
    record = ResearchMemoryRecord.model_validate(body)
    line = json.dumps(record.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    with (repo_root / _MEMORY_PATH).open("a", encoding="utf-8") as ledger:
        ledger.write(line + "\n")
    return body


def produce_handoff_cycle(
    repo_root: Path,
    *,
    receipt_id: str,
    producer_actor_id: str,
    summary: str,
    checkpoint_event_id: str,
    handoff_event_id: str,
    resource_event_id: str,
    source_verdict_event_id: str,
) -> dict[str, str]:
    """Run the complete evidence, ledger, and handoff cycle at the current head.

    Every step is verified by the committed tooling it feeds: the receipt by its typed
    contract, the ledger by `inbar memory verify`, and the final topology by
    `inbar handoff check`. A failure at any point leaves Git history recoverable by an
    ordinary reset and never rewrites an existing ledger byte.
    """
    root = repo_root.resolve(strict=True)
    if _git(root, "status", "--porcelain"):
        raise MemoryCycleError("refusing to start a handoff cycle on a dirty tree")
    implementation_commit = _git(root, "rev-parse", "HEAD")

    receipt_path = write_validation_receipt(
        root, receipt_id=receipt_id, producer_actor_id=producer_actor_id
    )
    receipt = EngineeringValidationReceipt.model_validate_json(receipt_path.read_bytes())
    if receipt.result != "pass":
        raise MemoryCycleError("validation receipt did not pass; the cycle records no checkpoint")
    if receipt.subject_commit != implementation_commit:
        raise MemoryCycleError("validation receipt does not bind the implementation head")

    _git(root, "add", f"evidence/validation/{receipt_id}")
    _git(root, "commit", "-q", "-m", "Record Inbar validation evidence")
    evidence_commit = _git(root, "rev-parse", "HEAD")

    receipt_uri = f"evidence/validation/{receipt_id}/receipt.json"
    receipt_bytes = (root / receipt_uri).read_bytes()
    receipt_binding = {
        "bytes": len(receipt_bytes),
        "git_commit": evidence_commit,
        "media_type": "application/json",
        "path": receipt_uri,
        "receipt_id": receipt_id,
        "sha256": hashlib.sha256(receipt_bytes).hexdigest(),
    }

    ledger = _load_ledger(root)
    previous = ledger[-1]
    previous_handoff = next(event for event in reversed(ledger) if event["event_type"] == "handoff")
    previous_verdict = next(
        event
        for event in reversed(ledger)
        if event["event_type"] == "finding"
        and event.get("links", {}).get("scope_correction") == _LEGACY_SOURCE_VERDICT_EVENT
    )

    resource_event = _append_event(
        root,
        previous=previous,
        event_id=resource_event_id,
        event_type="resource",
        stage="engineering-validation",
        status="recorded",
        actor_id=producer_actor_id,
        summary=(
            f"Recorded the unmetered engineering-validation resource boundary for {receipt_id}."
        ),
        payload={
            "authority_effect": "none",
            "cloud_jobs": None,
            "direct_cost_usd": None,
            "gpu_seconds": None,
            "independent_attestation": False,
            "measurement_status": "not_metered",
            "observation_boundary": (
                "Null quantities mean not measured, not zero; the frozen plan grants no "
                "resource-spend authority."
            ),
            "paid_calls": None,
            "receipt_result": receipt.result,
            "resource": receipt_id,
            "scientific_result": "not_evaluated",
        },
        evidence=[
            _evidence_ref(
                root,
                uri=receipt_uri,
                git_commit=evidence_commit,
                media_type="application/json",
                role="verifier",
            )
        ],
        links={"source_verdict": source_verdict_event_id},
        source_commit=evidence_commit,
    )

    # The current source-verdict finding is re-issued each cycle: the renderer requires its
    # source commit and its bound audit-document bytes to match the implementation head. The
    # verdict itself did not change, so the frozen payload and summary carry forward verbatim.
    verdict_event = _append_event(
        root,
        previous=resource_event,
        event_id=source_verdict_event_id,
        event_type="finding",
        stage="mission-handoff",
        status="negative",
        actor_id=producer_actor_id,
        summary=previous_verdict["summary"],
        payload=dict(previous_verdict["payload"]),
        evidence=[
            _evidence_ref(
                root,
                uri=_SOURCE_AUDIT_PATH,
                git_commit=implementation_commit,
                media_type="text/markdown",
                role="source",
            )
        ],
        links={"scope_correction": _LEGACY_SOURCE_VERDICT_EVENT},
        source_commit=implementation_commit,
    )

    checkpoint_event = _append_event(
        root,
        previous=verdict_event,
        event_id=checkpoint_event_id,
        event_type="execution",
        stage="mission-handoff",
        status="pass",
        actor_id=producer_actor_id,
        summary=summary,
        # The recovery pair is a frozen contract, not a narrative: the renderer requires these
        # exact strings, so they are imported from the renderer rather than restated.
        payload={
            "action": RECOVERY_CHECKPOINT_ACTION,
            "authority_effect": RECOVERY_CHECKPOINT_AUTHORITY_EFFECT,
            "handoff_contract": "inbar.handoff-checkpoint.v2",
            "implementation_commit": implementation_commit,
            "outcome": RECOVERY_CHECKPOINT_OUTCOME,
            "validation_receipt": receipt_binding,
        },
        evidence=[
            _evidence_ref(
                root,
                uri=_RENDERER_PATH,
                git_commit=implementation_commit,
                media_type="text/x-python",
                role="source",
            ),
            _evidence_ref(
                root,
                uri=receipt_uri,
                git_commit=evidence_commit,
                media_type="application/json",
                role="verifier",
            ),
        ],
        links={
            "resource_observation": resource_event_id,
            "source_verdict": source_verdict_event_id,
        },
        source_commit=evidence_commit,
    )

    _append_event(
        root,
        previous=checkpoint_event,
        event_id=handoff_event_id,
        event_type="handoff",
        stage="mission-handoff",
        status="blocked",
        actor_id=producer_actor_id,
        summary=(
            "Inbar remains blocked at the prospective acquisition-authority boundary "
            "after the recorded engineering checkpoint."
        ),
        payload=dict(previous_handoff["payload"]),
        evidence=[
            _evidence_ref(
                root,
                uri="CONTINUITY.md",
                git_commit=implementation_commit,
                media_type="text/markdown",
                role="source",
            )
        ],
        links={
            "checkpoint": checkpoint_event_id,
            "engine_boundary": _ENGINE_BOUNDARY_EVENT,
            "source_verdict": source_verdict_event_id,
        },
        source_commit=evidence_commit,
    )

    _run_inbar(root, "memory", "verify")
    _run_inbar(root, "handoff", "render")
    _git(root, "add", _MEMORY_PATH, _HANDOFF_PATH)
    staged = _git(root, "diff", "--cached", "--name-only").splitlines()
    if sorted(staged) != sorted([_MEMORY_PATH, _HANDOFF_PATH]):
        raise MemoryCycleError(f"final commit must change exactly two files, staged: {staged}")
    _git(root, "commit", "-q", "-m", "Finalize Inbar handoff")
    final_commit = _git(root, "rev-parse", "HEAD")

    _run_inbar(root, "handoff", "check")
    return {
        "implementation_commit": implementation_commit,
        "evidence_commit": evidence_commit,
        "final_commit": final_commit,
        "receipt_id": receipt_id,
    }
