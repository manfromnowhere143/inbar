from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "ci" / "verify_history.py"
_GENESIS_HASH = "0" * 64
_BOOTSTRAP_SHA = "b3cd7570a7b86e918e4831c3b57f7d4ca213d026"


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _memory_record(
    sequence: int,
    event_id: str,
    previous_hash: str,
    source_commit: str,
    *,
    evidence: list[dict[str, object]] | None = None,
    event_type: str = "finding",
    links: dict[str, str] | None = None,
    payload: dict[str, object] | None = None,
    stage: str = "ci-test",
    status: str = "recorded",
) -> tuple[bytes, str]:
    body = {
        "access": "internal",
        "actor": {"actor_id": "ci-test", "kind": "agent"},
        "corrects_event_id": None,
        "cost_usd": "0",
        "engine_requirement": None,
        "epistemic_phase": "retrospective",
        "event_id": event_id,
        "event_type": event_type,
        "evidence": evidence or [],
        "links": links or {},
        "manual_minutes": 0.0,
        "mission_id": "inbar",
        "occurred_at": "2026-07-15T00:00:00Z",
        "payload": payload or {"finding": f"test finding {sequence}"},
        "previous_event_hash": previous_hash,
        "recorded_at": "2026-07-15T00:00:01Z",
        "recurrence_key": None,
        "schema_version": "daniel.research-memory.v2",
        "sequence": sequence,
        "source_commit": source_commit,
        "stage": stage,
        "status": status,
        "summary": f"Test memory event {sequence}.",
    }
    event_hash = hashlib.sha256(_canonical_json(body)).hexdigest()
    return _canonical_json({**body, "event_hash": event_hash}) + b"\n", event_hash


def _append_memory_record(
    path: Path,
    event_id: str,
    *,
    source_commit: str | None = None,
    evidence: list[dict[str, object]] | None = None,
    event_type: str = "finding",
    links: dict[str, str] | None = None,
    payload: dict[str, object] | None = None,
    stage: str = "ci-test",
    status: str = "recorded",
) -> None:
    data = path.read_bytes()
    if data:
        records = [json.loads(line) for line in data.splitlines()]
        previous_hash = records[-1]["event_hash"]
        sequence = len(records)
    else:
        previous_hash = _GENESIS_HASH
        sequence = 0
    repo = path.parents[1]
    record, _ = _memory_record(
        sequence,
        event_id,
        previous_hash,
        source_commit or _git(repo, "rev-parse", "HEAD"),
        evidence=evidence,
        event_type=event_type,
        links=links,
        payload=payload,
        stage=stage,
        status=status,
    )
    path.write_bytes(data + record)


def _evidence(
    *,
    git_commit: str | None,
    uri: str,
    sha256: str,
    role: str = "source",
) -> list[dict[str, object]]:
    return [
        {
            "access": "internal",
            "git_commit": git_commit,
            "label_access": "none",
            "media_type": "text/plain",
            "role": role,
            "sha256": sha256,
            "uri": uri,
        }
    ]


def _git(repo: Path, *arguments: str) -> str:
    return subprocess.run(  # noqa: S603 - fixed executable with test-controlled arguments
        ["/usr/bin/git", *arguments],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    ).stdout.strip()


def _git_bytes(repo: Path, *arguments: str) -> bytes:
    return subprocess.run(  # noqa: S603 - fixed executable and test-controlled arguments
        ["/usr/bin/git", *arguments],
        cwd=repo,
        check=True,
        capture_output=True,
        timeout=20,
    ).stdout


def _commit(
    repo: Path,
    message: str,
    *,
    author_name: str = "Inbar CI Test",
    committer_name: str = "Inbar CI Test",
) -> str:
    _git(repo, "add", "-A")
    _git(
        repo,
        "-c",
        f"user.name={committer_name}",
        "-c",
        "user.email=inbar-ci@example.invalid",
        "commit",
        "--quiet",
        "--author",
        f"{author_name} <inbar-ci@example.invalid>",
        "-m",
        message,
    )
    return _git(repo, "rev-parse", "HEAD")


def _repository(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "--quiet", "-b", "main")
    (repo / "source.txt").write_text("trusted\n", encoding="utf-8")
    source_commit = _commit(repo, "source anchor")
    memory = repo / "memory" / "research_engine_extraction.jsonl"
    memory.parent.mkdir()
    base_record, _ = _memory_record(0, "base-event", _GENESIS_HASH, source_commit)
    memory.write_bytes(base_record)
    (repo / "HANDOFF.md").write_text("base handoff\n", encoding="utf-8")
    workflows = repo / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("name: protected-ci\n", encoding="utf-8")
    (workflows / "memory-integrity.yml").write_text("name: protected-memory\n", encoding="utf-8")
    verifier = repo / "scripts" / "ci" / "verify_history.py"
    verifier.parent.mkdir(parents=True)
    verifier.write_text("protected verifier\n", encoding="utf-8")
    return repo, _commit(repo, "base")


def _verify(repo: Path, base: str, head: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed interpreter and test-controlled arguments
        [
            sys.executable,
            str(_SCRIPT),
            "--repo",
            str(repo),
            "--base",
            base,
            "--head",
            head,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _verify_as_bootstrap(
    repo: Path,
    base: str,
    head: str,
    tmp_path: Path,
) -> subprocess.CompletedProcess[str]:
    source = _SCRIPT.read_text(encoding="utf-8")
    assert source.count(_BOOTSTRAP_SHA) == 1
    verifier = tmp_path / "bootstrap-verify-history.py"
    verifier.write_text(source.replace(_BOOTSTRAP_SHA, base), encoding="utf-8")
    return subprocess.run(  # noqa: S603 - patched fixed source and test-controlled arguments
        [
            sys.executable,
            str(verifier),
            "--repo",
            str(repo),
            "--base",
            base,
            "--head",
            head,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _bootstrap_implementation(repo: Path) -> str:
    (repo / "source.txt").write_text("bootstrap implementation\n", encoding="utf-8")
    (repo / ".github" / "workflows" / "ci.yml").write_text("name: bootstrap-ci\n", encoding="utf-8")
    (repo / ".github" / "workflows" / "memory-integrity.yml").write_text(
        "name: bootstrap-memory\n", encoding="utf-8"
    )
    (repo / "scripts" / "ci" / "verify_history.py").write_text(
        "bootstrap verifier\n", encoding="utf-8"
    )
    return _commit(repo, "bootstrap implementation")


def _bootstrap_final(
    repo: Path,
    *,
    checkpoint_implementation: str | None = None,
    evidence_commit: str | None = None,
    extra_path: str | None = None,
    recovery_source_commit: str | None = None,
) -> str:
    implementation = _git(repo, "rev-parse", "HEAD")
    anchored_evidence_commit = evidence_commit or implementation
    source_sha256 = hashlib.sha256(
        _git_bytes(repo, "show", f"{anchored_evidence_commit}:source.txt")
    ).hexdigest()
    source_evidence = _evidence(
        git_commit=anchored_evidence_commit,
        uri="source.txt",
        sha256=source_sha256,
    )
    verifier_evidence = _evidence(
        git_commit=anchored_evidence_commit,
        uri="source.txt",
        sha256=source_sha256,
        role="verifier",
    )
    memory = repo / "memory" / "research_engine_extraction.jsonl"
    checkpoint_id = "bootstrap-recovery-checkpoint"
    _append_memory_record(
        memory,
        checkpoint_id,
        source_commit=recovery_source_commit or implementation,
        evidence=[*source_evidence, *verifier_evidence],
        event_type="execution",
        payload={
            "action": "Verified bootstrap implementation.",
            "handoff_contract": "inbar.handoff-checkpoint.v1",
            "implementation_commit": checkpoint_implementation or implementation,
            "outcome": "Implementation checks passed.",
        },
        stage="mission-handoff",
        status="pass",
    )
    _append_memory_record(
        memory,
        "bootstrap-recovery-handoff",
        source_commit=recovery_source_commit or implementation,
        evidence=source_evidence,
        event_type="handoff",
        links={"checkpoint": checkpoint_id},
        payload={
            "handoff_contract": "inbar.handoff-state.v1",
            "next_action": "Keep authority blocked.",
            "state": "Bootstrap remains blocked.",
        },
        stage="mission-handoff",
        status="blocked",
    )
    (repo / "HANDOFF.md").write_text("generated final handoff\n", encoding="utf-8")
    if extra_path is not None:
        candidate = repo / extra_path
        candidate.parent.mkdir(parents=True, exist_ok=True)
        candidate.write_text("unreviewed final change\n", encoding="utf-8")
    return _commit(repo, "bootstrap memory and handoff")


def _append_mutated_memory(path: Path, mutation: str) -> None:
    data = path.read_bytes()
    records = [json.loads(line) for line in data.splitlines()]
    record_bytes, _ = _memory_record(
        len(records),
        f"invalid-{mutation}",
        records[-1]["event_hash"],
        _git(path.parents[1], "rev-parse", "HEAD"),
    )
    record = json.loads(record_bytes)
    if mutation == "actor-kind":
        record["actor"]["kind"] = "reviewer"
    elif mutation == "naive-timestamp":
        record["occurred_at"] = "2026-07-15T00:00:00"
    elif mutation == "recorded-before-occurred":
        record["occurred_at"] = "2026-07-15T00:00:02Z"
    elif mutation == "status":
        record["status"] = "trusted"
    elif mutation == "external-evidence":
        record["evidence"] = [
            {
                "access": "internal",
                "git_commit": None,
                "label_access": "none",
                "media_type": "text/plain",
                "role": "source",
                "sha256": "2" * 64,
                "uri": "http://example.invalid/evidence.txt",
            }
        ]
    elif mutation == "sealed-public-evidence":
        record["evidence"] = [
            {
                "access": "public",
                "git_commit": "1" * 40,
                "label_access": "sealed_heldout",
                "media_type": "text/plain",
                "role": "source",
                "sha256": "2" * 64,
                "uri": "source.txt",
            }
        ]
    elif mutation == "cost":
        record["cost_usd"] = "-1"
    elif mutation == "manual-minutes":
        record["manual_minutes"] = -1.0
    elif mutation == "manual-recurrence":
        record["event_type"] = "manual_work"
        record["payload"] = {"task": "review"}
        record["recurrence_key"] = None
    elif mutation == "sensitive-payload":
        record["payload"]["api_token"] = "redacted-fixture-value"  # noqa: S105
    else:  # pragma: no cover - test helper guard
        raise AssertionError(f"unknown mutation: {mutation}")
    body = dict(record)
    body.pop("event_hash")
    record["event_hash"] = hashlib.sha256(_canonical_json(body)).hexdigest()
    path.write_bytes(data + _canonical_json(record) + b"\n")


def test_history_verifier_accepts_strict_append_only_commits(tmp_path: Path) -> None:
    repo, base = _repository(tmp_path)
    memory = repo / "memory" / "research_engine_extraction.jsonl"
    _append_memory_record(memory, "next-event")
    head = _commit(repo, "append memory")

    result = _verify(repo, base, head)

    assert result.returncode == 0, result.stderr
    assert "HISTORY_VERIFIED commits=1 edges=1" in result.stdout


def test_history_verifier_resolves_repository_evidence_and_exact_blob_hash(
    tmp_path: Path,
) -> None:
    repo, base = _repository(tmp_path)
    memory = repo / "memory" / "research_engine_extraction.jsonl"
    _append_memory_record(
        memory,
        "anchored-evidence",
        evidence=_evidence(
            git_commit=base,
            uri="source.txt",
            sha256=hashlib.sha256(b"trusted\n").hexdigest(),
        ),
    )
    head = _commit(repo, "append anchored evidence")

    result = _verify(repo, base, head)

    assert result.returncode == 0, result.stderr


def test_history_verifier_rejects_a_git_commit_on_external_https_evidence(
    tmp_path: Path,
) -> None:
    repo, base = _repository(tmp_path)
    memory = repo / "memory" / "research_engine_extraction.jsonl"
    _append_memory_record(
        memory,
        "external-evidence",
        evidence=_evidence(
            git_commit="f" * 40,
            uri="https://example.invalid/evidence.txt",
            sha256="2" * 64,
        ),
    )
    head = _commit(repo, "append external evidence")

    result = _verify(repo, base, head)

    assert result.returncode == 1
    assert "external research memory evidence must not include a Git commit" in result.stderr


def test_history_verifier_accepts_hash_only_external_https_evidence(tmp_path: Path) -> None:
    repo, base = _repository(tmp_path)
    memory = repo / "memory" / "research_engine_extraction.jsonl"
    _append_memory_record(
        memory,
        "external-evidence",
        evidence=_evidence(
            git_commit=None,
            uri="https://example.invalid/evidence.txt",
            sha256="2" * 64,
        ),
    )
    head = _commit(repo, "append external evidence")

    result = _verify(repo, base, head)

    assert result.returncode == 0, result.stderr


def test_history_verifier_rejects_external_https_evidence_without_a_hash(
    tmp_path: Path,
) -> None:
    repo, base = _repository(tmp_path)
    memory = repo / "memory" / "research_engine_extraction.jsonl"
    evidence = _evidence(
        git_commit=None,
        uri="https://example.invalid/evidence.txt",
        sha256="2" * 64,
    )
    evidence[0]["sha256"] = None
    _append_memory_record(memory, "external-evidence", evidence=evidence)
    head = _commit(repo, "append external evidence")

    result = _verify(repo, base, head)

    assert result.returncode == 1
    assert "external research memory evidence lacks a hash" in result.stderr


def test_history_verifier_rejects_a_nonexistent_memory_source_commit(tmp_path: Path) -> None:
    repo, base = _repository(tmp_path)
    memory = repo / "memory" / "research_engine_extraction.jsonl"
    _append_memory_record(memory, "missing-source", source_commit="f" * 40)
    head = _commit(repo, "append missing source")

    result = _verify(repo, base, head)

    assert result.returncode == 1
    assert "source commit does not resolve to a commit" in result.stderr


def test_history_verifier_rejects_a_nonancestor_memory_source_commit(tmp_path: Path) -> None:
    repo, base = _repository(tmp_path)
    _git(repo, "checkout", "--quiet", "-b", "unrelated-source", base)
    (repo / "unrelated.txt").write_text("unrelated\n", encoding="utf-8")
    unrelated = _commit(repo, "unrelated source")
    _git(repo, "checkout", "--quiet", "main")
    memory = repo / "memory" / "research_engine_extraction.jsonl"
    _append_memory_record(memory, "nonancestor-source", source_commit=unrelated)
    head = _commit(repo, "append nonancestor source")

    result = _verify(repo, base, head)

    assert result.returncode == 1
    assert "source commit is not an ancestor" in result.stderr


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        ("absent.txt", "is not a Git blob"),
        ("memory", "is not a Git blob"),
    ],
)
def test_history_verifier_rejects_missing_or_nonblob_repository_evidence(
    uri: str,
    expected: str,
    tmp_path: Path,
) -> None:
    repo, base = _repository(tmp_path)
    memory = repo / "memory" / "research_engine_extraction.jsonl"
    _append_memory_record(
        memory,
        "invalid-evidence-path",
        evidence=_evidence(git_commit=base, uri=uri, sha256="2" * 64),
    )
    head = _commit(repo, "append invalid evidence path")

    result = _verify(repo, base, head)

    assert result.returncode == 1
    assert expected in result.stderr


def test_history_verifier_rejects_a_repository_evidence_hash_mismatch(
    tmp_path: Path,
) -> None:
    repo, base = _repository(tmp_path)
    memory = repo / "memory" / "research_engine_extraction.jsonl"
    _append_memory_record(
        memory,
        "mismatched-evidence",
        evidence=_evidence(git_commit=base, uri="source.txt", sha256="2" * 64),
    )
    head = _commit(repo, "append mismatched evidence")

    result = _verify(repo, base, head)

    assert result.returncode == 1
    assert "evidence hash mismatch" in result.stderr


@pytest.mark.parametrize("relationship", ["nonexistent", "nonancestor"])
def test_history_verifier_rejects_unreachable_repository_evidence_commits(
    relationship: str,
    tmp_path: Path,
) -> None:
    repo, base = _repository(tmp_path)
    if relationship == "nonexistent":
        evidence_commit = "f" * 40
    else:
        _git(repo, "checkout", "--quiet", "-b", "unrelated-evidence", base)
        (repo / "unrelated-evidence.txt").write_text("unrelated\n", encoding="utf-8")
        evidence_commit = _commit(repo, "unrelated evidence")
        _git(repo, "checkout", "--quiet", "main")
    memory = repo / "memory" / "research_engine_extraction.jsonl"
    _append_memory_record(
        memory,
        "unreachable-evidence",
        evidence=_evidence(
            git_commit=evidence_commit,
            uri="source.txt",
            sha256=hashlib.sha256(b"trusted\n").hexdigest(),
        ),
    )
    head = _commit(repo, "append unreachable evidence")

    result = _verify(repo, base, head)

    assert result.returncode == 1
    if relationship == "nonexistent":
        assert "evidence commit does not resolve to a commit" in result.stderr
    else:
        assert "evidence commit is not an ancestor" in result.stderr


def test_history_verifier_accepts_exact_two_commit_bootstrap_ceremony(tmp_path: Path) -> None:
    repo, base = _repository(tmp_path)
    _bootstrap_implementation(repo)
    head = _bootstrap_final(repo)

    result = _verify_as_bootstrap(repo, base, head, tmp_path)

    assert result.returncode == 0, result.stderr
    assert "HISTORY_VERIFIED commits=2 edges=2" in result.stdout


def test_history_verifier_rejects_bootstrap_source_changes_in_final_commit(
    tmp_path: Path,
) -> None:
    repo, base = _repository(tmp_path)
    _bootstrap_implementation(repo)
    head = _bootstrap_final(repo, extra_path="src/fieldtrue/acquisition.py")

    result = _verify_as_bootstrap(repo, base, head, tmp_path)

    assert result.returncode == 1
    assert "final commit must change only memory and handoff" in result.stderr


def test_history_verifier_rejects_bootstrap_checkpoint_attributed_to_an_older_commit(
    tmp_path: Path,
) -> None:
    repo, base = _repository(tmp_path)
    _bootstrap_implementation(repo)
    head = _bootstrap_final(repo, checkpoint_implementation=base)

    result = _verify_as_bootstrap(repo, base, head, tmp_path)

    assert result.returncode == 1
    assert "checkpoint does not bind the implementation commit" in result.stderr


@pytest.mark.parametrize("anchor_kind", ["evidence", "source"])
def test_history_verifier_rejects_bootstrap_recovery_anchors_to_an_older_commit(
    anchor_kind: str,
    tmp_path: Path,
) -> None:
    repo, base = _repository(tmp_path)
    _bootstrap_implementation(repo)
    head = _bootstrap_final(
        repo,
        evidence_commit=base if anchor_kind == "evidence" else None,
        recovery_source_commit=base if anchor_kind == "source" else None,
    )

    result = _verify_as_bootstrap(repo, base, head, tmp_path)

    assert result.returncode == 1
    assert "implementation commit" in result.stderr


def test_history_verifier_rejects_bootstrap_final_artifacts_in_implementation(
    tmp_path: Path,
) -> None:
    repo, base = _repository(tmp_path)
    (repo / "HANDOFF.md").write_text("premature handoff\n", encoding="utf-8")
    _bootstrap_implementation(repo)
    head = _bootstrap_final(repo)

    result = _verify_as_bootstrap(repo, base, head, tmp_path)

    assert result.returncode == 1
    assert "implementation commit changed memory or handoff" in result.stderr


def test_history_verifier_rejects_non_linear_two_commit_bootstrap(tmp_path: Path) -> None:
    repo, base = _repository(tmp_path)
    _git(repo, "checkout", "--quiet", "-b", "implementation", base)
    implementation = _bootstrap_implementation(repo)
    _git(repo, "checkout", "--quiet", "main")
    _git(
        repo,
        "-c",
        "user.name=Inbar CI Test",
        "-c",
        "user.email=inbar-ci@example.invalid",
        "merge",
        "--quiet",
        "--no-ff",
        "-m",
        "merge bootstrap implementation",
        implementation,
    )
    head = _git(repo, "rev-parse", "HEAD")

    result = _verify_as_bootstrap(repo, base, head, tmp_path)

    assert result.returncode == 1
    assert "two-commit linear history" in result.stderr


@pytest.mark.parametrize(
    "mutation",
    [
        "actor-kind",
        "naive-timestamp",
        "recorded-before-occurred",
        "status",
        "external-evidence",
        "sealed-public-evidence",
        "cost",
        "manual-minutes",
        "manual-recurrence",
        "sensitive-payload",
    ],
)
def test_history_rejects_invalid_canonical_memory_despite_weakened_candidate_verifier(
    mutation: str,
    tmp_path: Path,
) -> None:
    repo, base = _repository(tmp_path)
    memory = repo / "memory" / "research_engine_extraction.jsonl"
    _append_mutated_memory(memory, mutation)
    candidate_verifier = repo / "src" / "fieldtrue" / "memory.py"
    candidate_verifier.parent.mkdir(parents=True)
    candidate_verifier.write_text(
        "def verify_memory(_path):\n    return (1, 'accepted')\n",
        encoding="utf-8",
    )
    head = _commit(repo, "weaken candidate memory verifier")

    result = _verify(repo, base, head)

    assert result.returncode == 1
    assert "research memory" in result.stderr


def test_history_verifier_rejects_tamper_then_restore(tmp_path: Path) -> None:
    repo, base = _repository(tmp_path)
    memory = repo / "memory" / "research_engine_extraction.jsonl"
    base_memory = memory.read_bytes()
    rewritten, _ = _memory_record(
        0,
        "rewritten-event",
        _GENESIS_HASH,
        _git(repo, "rev-parse", "HEAD"),
    )
    memory.write_bytes(rewritten)
    _commit(repo, "rewrite memory")
    memory.write_bytes(base_memory)
    _append_memory_record(memory, "next-event")
    head = _commit(repo, "restore and append")

    result = _verify(repo, base, head)

    assert result.returncode == 1
    assert "research memory is not append-only" in result.stderr


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        ("binary-credential", "credential signature detected"),
        ("credential-message", "credential signature detected in commit metadata"),
        ("credential-path", "credential signature detected in path"),
        ("forbidden-path", "forbidden tracked path"),
        ("text-credential", "credential signature detected"),
        ("tracked-attributes", "tracked Git attributes"),
        ("tracked-attributes-case", "tracked Git attributes"),
    ],
)
def test_history_verifier_scans_intermediate_trees_without_disclosing_content(
    kind: str,
    expected: str,
    tmp_path: Path,
) -> None:
    repo, base = _repository(tmp_path)
    credential = "AKIA" + "A" * 16
    candidate: Path | None
    message = "introduce forbidden content"
    if kind == "binary-credential":
        candidate = repo / "temporary.bin"
        candidate.write_bytes(b"\x00" + credential.encode("ascii") + b"\x00")
    elif kind == "credential-message":
        candidate = repo / "message-marker.txt"
        candidate.write_text("marker\n", encoding="utf-8")
        message = f"candidate message {credential}"
    elif kind == "credential-path":
        candidate = repo / f"candidate-{credential}.txt"
        candidate.write_text("path marker\n", encoding="utf-8")
    elif kind == "text-credential":
        candidate = repo / "temporary.txt"
        candidate.write_text(credential + "\n", encoding="utf-8")
    elif kind == "forbidden-path":
        candidate = repo / "data" / "raw" / "temporary.bin"
        candidate.parent.mkdir(parents=True)
        candidate.write_bytes(b"temporary\n")
    else:
        candidate = repo / (
            ".GITATTRIBUTES" if kind == "tracked-attributes-case" else ".gitattributes"
        )
        candidate.write_text("*.bin binary\n", encoding="utf-8")
    _commit(repo, message)
    candidate.unlink()
    head = _commit(repo, "remove forbidden content")

    result = _verify(repo, base, head)

    assert result.returncode == 1
    assert expected in result.stderr
    assert credential not in result.stdout + result.stderr


@pytest.mark.parametrize(
    "credential",
    [
        "AS" + "IA" + "A" * 16,
        "sk-" + "proj-" + "B" * 24,
        "sk-" + "ant-" + "C" * 24,
        "AI" + "za" + "D" * 35,
        "gl" + "pat-" + "E" * 24,
        "xo" + "xb-" + "1" * 24,
        "sk_" + "live_" + "F" * 20,
        "git" + "hub_pat_" + "K" * 24,
        "np" + "m_" + "G" * 36,
        "py" + "pi-" + "H" * 44,
        "h" + "f_" + "I" * 24,
        "ya" + "29." + "J" * 24,
    ],
)
def test_history_verifier_rejects_modern_credential_signatures_without_disclosure(
    credential: str,
    tmp_path: Path,
) -> None:
    repo, base = _repository(tmp_path)
    (repo / "candidate.txt").write_text(f"{credential}\n", encoding="utf-8")
    head = _commit(repo, "candidate credential")

    result = _verify(repo, base, head)

    assert result.returncode == 1
    assert "credential signature detected" in result.stderr
    assert credential not in result.stdout + result.stderr


@pytest.mark.parametrize("header", ["author", "committer"])
def test_history_verifier_scans_raw_commit_identity_headers(
    header: str,
    tmp_path: Path,
) -> None:
    repo, base = _repository(tmp_path)
    credential = "AS" + "IA" + "K" * 16
    (repo / "identity-marker.txt").write_text("marker\n", encoding="utf-8")
    names = {
        "author_name": credential if header == "author" else "Inbar CI Test",
        "committer_name": credential if header == "committer" else "Inbar CI Test",
    }
    head = _commit(repo, "identity metadata", **names)

    result = _verify(repo, base, head)

    assert result.returncode == 1
    assert "credential signature detected in commit metadata" in result.stderr
    assert credential not in result.stdout + result.stderr


@pytest.mark.parametrize(
    "relative_path",
    [
        "data/raw",
        "data/derived",
        ".local",
        "data/raw/item",
        "data/derived/item",
        ".local/item",
        "DATA/RAW/item",
        ".LOCAL/item",
    ],
)
def test_history_verifier_rejects_exact_and_descendant_data_roots(
    relative_path: str,
    tmp_path: Path,
) -> None:
    repo, base = _repository(tmp_path)
    candidate = repo / relative_path
    candidate.parent.mkdir(parents=True, exist_ok=True)
    candidate.write_text("forbidden\n", encoding="utf-8")
    head = _commit(repo, "forbidden data root")

    result = _verify(repo, base, head)

    assert result.returncode == 1
    assert "forbidden tracked path" in result.stderr


def test_history_verifier_rejects_a_partial_intermediate_memory_record(tmp_path: Path) -> None:
    repo, base = _repository(tmp_path)
    memory = repo / "memory" / "research_engine_extraction.jsonl"
    base_memory = memory.read_bytes()
    base_hash = json.loads(base_memory)["event_hash"]
    next_record, _ = _memory_record(
        1,
        "next-event",
        base_hash,
        _git(repo, "rev-parse", "HEAD"),
    )
    midpoint = len(next_record) // 2
    memory.write_bytes(base_memory + next_record[:midpoint])
    _commit(repo, "interrupt memory append")
    memory.write_bytes(base_memory + next_record)
    head = _commit(repo, "complete memory append")

    result = _verify(repo, base, head)

    assert result.returncode == 1
    assert "research memory" in result.stderr


def test_history_verifier_rejects_an_invalid_intermediate_memory_hash(tmp_path: Path) -> None:
    repo, base = _repository(tmp_path)
    memory = repo / "memory" / "research_engine_extraction.jsonl"
    base_memory = memory.read_bytes()
    base_hash = json.loads(base_memory)["event_hash"]
    next_record, _ = _memory_record(
        1,
        "next-event",
        base_hash,
        _git(repo, "rev-parse", "HEAD"),
    )
    invalid = json.loads(next_record)
    invalid["event_hash"] = "f" * 64
    memory.write_bytes(base_memory + _canonical_json(invalid) + b"\n")
    _commit(repo, "append invalid memory hash")
    memory.write_bytes(base_memory + next_record)
    head = _commit(repo, "repair memory hash")

    result = _verify(repo, base, head)

    assert result.returncode == 1
    assert "research memory event hash mismatch" in result.stderr


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        ("crlf", "exact LF framing"),
        ("duplicate-key", "duplicate object key"),
        ("noncanonical", "not canonical JSON"),
    ],
)
def test_history_verifier_rejects_noncanonical_intermediate_memory(
    kind: str,
    expected: str,
    tmp_path: Path,
) -> None:
    repo, base = _repository(tmp_path)
    memory = repo / "memory" / "research_engine_extraction.jsonl"
    base_memory = memory.read_bytes()
    base_hash = json.loads(base_memory)["event_hash"]
    next_record, _ = _memory_record(
        1,
        "next-event",
        base_hash,
        _git(repo, "rev-parse", "HEAD"),
    )
    if kind == "crlf":
        invalid_record = next_record.replace(b"\n", b"\r\n")
    elif kind == "duplicate-key":
        invalid_record = next_record.replace(
            b'{"access":"internal",',
            b'{"access":"internal","access":"internal",',
            1,
        )
    else:
        invalid_record = b" " + next_record
    memory.write_bytes(base_memory + invalid_record)
    _commit(repo, "append noncanonical memory")
    memory.write_bytes(base_memory + next_record)
    head = _commit(repo, "repair memory framing")

    result = _verify(repo, base, head)

    assert result.returncode == 1
    assert expected in result.stderr


def test_history_verifier_rejects_tracked_symlinks(tmp_path: Path) -> None:
    repo, base = _repository(tmp_path)
    (repo / "redirect").symlink_to("source.txt")
    head = _commit(repo, "add symlink")

    result = _verify(repo, base, head)

    assert result.returncode == 1
    assert "symlink, submodule, or special entry" in result.stderr


@pytest.mark.parametrize(
    "relative_path",
    [
        ".github/workflows/ci.yml",
        ".github/workflows/memory-integrity.yml",
        ".github/workflows/unreviewed.yml",
        "scripts/ci/verify_history.py",
    ],
)
def test_history_verifier_rejects_changes_to_protected_ci_policy_roots(
    relative_path: str,
    tmp_path: Path,
) -> None:
    repo, base = _repository(tmp_path)
    policy = repo / relative_path
    policy.parent.mkdir(parents=True, exist_ok=True)
    policy.write_text("changed policy\n", encoding="utf-8")
    head = _commit(repo, "change protected policy")

    result = _verify(repo, base, head)

    assert result.returncode == 1
    assert "protected CI policy changed" in result.stderr


def test_history_verifier_checks_every_parent_edge_of_a_merge(tmp_path: Path) -> None:
    repo, base = _repository(tmp_path)
    _git(repo, "checkout", "--quiet", "-b", "side", base)
    (repo / "side.txt").write_text("side\n", encoding="utf-8")
    _commit(repo, "side branch")

    _git(repo, "checkout", "--quiet", "main")
    memory = repo / "memory" / "research_engine_extraction.jsonl"
    _append_memory_record(memory, "main-event")
    _commit(repo, "main branch")
    _git(
        repo,
        "-c",
        "user.name=Inbar CI Test",
        "-c",
        "user.email=inbar-ci@example.invalid",
        "merge",
        "--quiet",
        "--no-ff",
        "-m",
        "merge side",
        "side",
    )
    head = _git(repo, "rev-parse", "HEAD")

    result = _verify(repo, base, head)

    assert result.returncode == 0, result.stderr
    assert "HISTORY_VERIFIED commits=3 edges=4" in result.stdout


def test_history_verifier_rejects_protected_policy_change_on_second_merge_parent(
    tmp_path: Path,
) -> None:
    repo, root = _repository(tmp_path)
    _git(repo, "checkout", "--quiet", "-b", "altered-policy", root)
    policy = repo / ".github" / "workflows" / "ci.yml"
    policy.write_text("name: altered-policy\n", encoding="utf-8")
    altered_parent = _commit(repo, "alter policy on side branch")

    _git(repo, "checkout", "--quiet", "main")
    (repo / "main.txt").write_text("main\n", encoding="utf-8")
    _commit(repo, "main branch")
    _git(
        repo,
        "-c",
        "user.name=Inbar CI Test",
        "-c",
        "user.email=inbar-ci@example.invalid",
        "merge",
        "--quiet",
        "--no-ff",
        "-s",
        "ours",
        "-m",
        "merge altered policy without its tree",
        "altered-policy",
    )
    head = _git(repo, "rev-parse", "HEAD")

    result = _verify(repo, altered_parent, head)

    assert result.returncode == 1
    assert "protected CI policy changed" in result.stderr


def test_ci_workflows_keep_history_runs_unique_and_bootstrap_fallback_narrow() -> None:
    root = Path(__file__).resolve().parents[2]
    workflow = (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    target = (root / ".github" / "workflows" / "memory-integrity.yml").read_text(encoding="utf-8")

    assert "group: ${{ github.workflow }}-${{ github.run_id }}" in workflow
    assert "group: ${{ github.workflow }}-${{ github.run_id }}" in target
    assert "cancel-in-progress: false" in workflow
    assert "cancel-in-progress: false" in target
    assert workflow.count("b3cd7570a7b86e918e4831c3b57f7d4ca213d026") == 1
    assert '"${EVENT_NAME}" == "push"' in workflow
    assert '"${head_commit}:scripts/ci/verify_history.py"' in workflow
    assert "cp scripts/ci/verify_history.py" not in workflow
    assert "persist-credentials: true" not in target
    assert "persist-credentials: false" in target
    assert "INBAR_FETCH_TOKEN: ${{ github.token }}" in target
    assert "GIT_CONFIG_COUNT=1" in target
    assert "GIT_CONFIG_KEY_0=http.https://github.com/.extraheader" in target
    assert 'git fetch --no-tags --no-recurse-submodules origin "${EXPECTED_HEAD}"' in target
    assert "refs/pull/" not in target
    assert "git config --local --name-only --list" in target
    assert "git config --includes --name-only --list" in target
    assert "Effective Git credential header remains" in target


def test_checkout_v7_includeif_requires_effective_config_inspection(tmp_path: Path) -> None:
    repo, _ = _repository(tmp_path)
    credential_config = tmp_path / "git-credentials-fixture.config"
    _git(
        repo,
        "config",
        "--file",
        str(credential_config),
        "http.https://github.com/.extraheader",
        "AUTHORIZATION: basic redacted-fixture",
    )
    include_key = f"includeIf.gitdir:{repo / '.git'}.path"
    _git(repo, "config", "--local", include_key, str(credential_config))

    local_names = _git(repo, "config", "--local", "--name-only", "--list").casefold()
    effective_names = _git(repo, "config", "--includes", "--name-only", "--list").casefold()

    assert "extraheader" not in local_names
    assert "includeif.gitdir:" in local_names
    assert "http.https://github.com/.extraheader" in effective_names
