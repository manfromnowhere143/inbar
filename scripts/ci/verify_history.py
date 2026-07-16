#!/usr/bin/env python3
"""Verify append-only and repository-content policy across an exact Git range."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
from datetime import datetime
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

_GIT = Path("/usr/bin/git")
_MEMORY_PATH = "memory/research_engine_extraction.jsonl"
_HANDOFF_PATH = "HANDOFF.md"
_MAX_COMMITS = 512
_MAX_GIT_OUTPUT = 32 * 1024 * 1024
_MAX_COMMIT_BYTES = 1024 * 1024
_MAX_MEMORY_BYTES = 16 * 1024 * 1024
_MAX_EVIDENCE_BLOB_BYTES = 16 * 1024 * 1024
_MAX_ANCHOR_BLOB_BYTES = 256 * 1024 * 1024
_MAX_ANCHOR_COMMITS = 4096
_MAX_ANCHOR_RELATIONS = 32 * 1024
_MAX_ANCHOR_BLOBS = 8192
_OID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CREDENTIAL_PATTERN = (
    r"BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY|"
    r"(AKIA|ASIA)[0-9A-Z]{16}|"
    r"gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"sk-proj-[A-Za-z0-9_-]{20,}|"
    r"sk-ant-[A-Za-z0-9_-]{20,}|"
    r"AIza[0-9A-Za-z_-]{35}|"
    r"glpat-[A-Za-z0-9_-]{20,}|"
    r"xox[baprs]-[0-9A-Za-z-]{20,}|"
    r"(sk|rk)_(live|test)_[0-9A-Za-z]{16,}|"
    r"npm_[0-9A-Za-z]{36}|"
    r"pypi-[0-9A-Za-z_-]{40,}|"
    r"hf_[0-9A-Za-z]{20,}|"
    r"ya29\.[0-9A-Za-z_-]{20,}|"
    r"sk-[A-Za-z0-9]{20,}"
)
_CREDENTIAL_RE = re.compile(_CREDENTIAL_PATTERN)
_CREDENTIAL_BYTES_RE = re.compile(_CREDENTIAL_PATTERN.encode("ascii"))
_MEMORY_GENESIS_HASH = "0" * 64
# This is the only edge whose parent predates the policy files. Its candidate
# policy requires a separate manual audit and is never described as base-controlled.
_POLICY_BOOTSTRAP_BASE = "b3cd7570a7b86e918e4831c3b57f7d4ca213d026"
_PROTECTED_POLICY_ROOTS = (".github/workflows", "scripts/ci/verify_history.py")
_BOOTSTRAP_FINAL_PATHS = frozenset({_HANDOFF_PATH, _MEMORY_PATH})
_BOOTSTRAP_REQUIRED_IMPLEMENTATION_PATHS = frozenset(
    {
        ".github/workflows/ci.yml",
        ".github/workflows/memory-integrity.yml",
        "scripts/ci/verify_history.py",
    }
)
_BOOTSTRAP_CHECKPOINT_CONTRACT = "inbar.handoff-checkpoint.v1"
_BOOTSTRAP_HANDOFF_CONTRACT = "inbar.handoff-state.v1"
_MEMORY_FIELDS = frozenset(
    {
        "access",
        "actor",
        "corrects_event_id",
        "cost_usd",
        "engine_requirement",
        "epistemic_phase",
        "event_hash",
        "event_id",
        "event_type",
        "evidence",
        "links",
        "manual_minutes",
        "mission_id",
        "occurred_at",
        "payload",
        "previous_event_hash",
        "recorded_at",
        "recurrence_key",
        "schema_version",
        "sequence",
        "source_commit",
        "stage",
        "status",
        "summary",
    }
)
_MEMORY_IDENTITIES = {
    ("daniel.research-memory.v1", "fieldtrue"),
    ("daniel.research-memory.v2", "inbar"),
}
_MEMORY_ACTOR_FIELDS = frozenset({"actor_id", "kind"})
_MEMORY_EVIDENCE_FIELDS = frozenset(
    {"access", "git_commit", "label_access", "media_type", "role", "sha256", "uri"}
)
_MEMORY_ACTOR_KINDS = frozenset({"human", "agent", "system"})
_MEMORY_EPISTEMIC_PHASES = frozenset({"prospective", "exploratory", "retrospective"})
_MEMORY_STATUSES = frozenset(
    {
        "pending",
        "recorded",
        "pass",
        "negative",
        "null",
        "blocked",
        "invalid",
        "void",
        "interrupted",
        "superseded",
    }
)
_MEMORY_ACCESS_CLASSES = frozenset({"public", "internal", "restricted"})
_MEMORY_LABEL_ACCESS = frozenset({"none", "development", "sealed_heldout"})
_MEMORY_EVIDENCE_ROLES = frozenset({"input", "raw", "derived", "verifier", "source", "approval"})
_MEMORY_COST = re.compile(r"^(0|[1-9][0-9]*)(\.[0-9]{1,6})?$")
_SENSITIVE_MEMORY_KEY_TERMS = (
    "credential",
    "hidden_label",
    "password",
    "private_key",
    "secret",
    "token",
)
_REQUIRED_PAYLOAD_FIELDS = {
    "source": frozenset({"source"}),
    "decision": frozenset({"decision"}),
    "protocol": frozenset({"protocol"}),
    "execution": frozenset({"action", "outcome"}),
    "finding": frozenset({"finding"}),
    "failure": frozenset({"failure"}),
    "correction": frozenset({"old", "corrected"}),
    "resource": frozenset({"resource"}),
    "manual_work": frozenset({"task"}),
    "handoff": frozenset({"state", "next_action"}),
    "naming": frozenset({"candidate", "verdict"}),
}


class HistoryVerificationError(ValueError):
    """The candidate history violates an integration invariant."""


class _AnchorCache:
    """Bound repeated immutable Git-anchor work across memory snapshots."""

    def __init__(self) -> None:
        self.resolved_commits: set[str] = set()
        self.ancestor_relations: set[tuple[str, str]] = set()
        self.blob_digests: dict[tuple[str, str], str] = {}
        self.blob_bytes = 0


def _git_environment() -> dict[str, str]:
    environment = {
        key: os.environ[key] for key in ("SYSTEMROOT", "TEMP", "TMP", "TMPDIR") if key in os.environ
    }
    environment.update(
        {
            "GIT_ALLOW_PROTOCOL": "",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_COUNT": "2",
            "GIT_CONFIG_KEY_0": "core.fsmonitor",
            "GIT_CONFIG_KEY_1": "core.hooksPath",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_VALUE_0": "false",
            "GIT_CONFIG_VALUE_1": os.devnull,
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_PAGER": "cat",
            "GIT_PROTOCOL_FROM_USER": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": "/nonexistent",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        }
    )
    return environment


def _trusted_git() -> str:
    try:
        metadata = _GIT.lstat()
    except OSError as error:
        raise HistoryVerificationError("fixed system Git is unavailable") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not metadata.st_mode & stat.S_IXUSR
    ):
        raise HistoryVerificationError("fixed system Git has unsafe ownership or mode")
    return str(_GIT)


def _run_git(
    repo: Path,
    *arguments: str,
    check: bool = True,
    text: bool = False,
) -> subprocess.CompletedProcess[bytes] | subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(  # noqa: S603 - fixed verified Git and internal arguments
            [_trusted_git(), *arguments],
            cwd=repo,
            check=False,
            capture_output=True,
            env=_git_environment(),
            text=text,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise HistoryVerificationError("Git history inspection failed") from error
    stdout_size = len(result.stdout.encode() if isinstance(result.stdout, str) else result.stdout)
    stderr_size = len(result.stderr.encode() if isinstance(result.stderr, str) else result.stderr)
    if stdout_size > _MAX_GIT_OUTPUT or stderr_size > _MAX_GIT_OUTPUT:
        raise HistoryVerificationError("Git history inspection exceeded its output bound")
    if check and result.returncode != 0:
        raise HistoryVerificationError("Git history inspection returned a failure")
    return result


def _validate_oid(value: str, label: str) -> str:
    if _OID.fullmatch(value) is None:
        raise HistoryVerificationError(f"{label} is not a full Git object ID")
    return value


def _verify_commit(repo: Path, commit: str, label: str) -> None:
    _validate_oid(commit, label)
    result = _run_git(repo, "cat-file", "-e", f"{commit}^{{commit}}", check=False)
    if result.returncode != 0:
        raise HistoryVerificationError(f"{label} does not resolve to a commit")


def _verify_anchor_commit(
    repo: Path,
    anchor: str,
    containing_commit: str,
    cache: _AnchorCache,
    *,
    label: str,
) -> None:
    if anchor not in cache.resolved_commits:
        if len(cache.resolved_commits) >= _MAX_ANCHOR_COMMITS:
            raise HistoryVerificationError("research memory commit anchors exceed the review bound")
        _verify_commit(repo, anchor, label)
        cache.resolved_commits.add(anchor)

    relation = (anchor, containing_commit)
    if relation in cache.ancestor_relations:
        return
    if len(cache.ancestor_relations) >= _MAX_ANCHOR_RELATIONS:
        raise HistoryVerificationError("research memory ancestry checks exceed the review bound")
    ancestry = _run_git(
        repo,
        "merge-base",
        "--is-ancestor",
        anchor,
        containing_commit,
        check=False,
    )
    if ancestry.returncode == 1:
        raise HistoryVerificationError(f"{label} is not an ancestor of its containing commit")
    if ancestry.returncode != 0:
        raise HistoryVerificationError(f"{label} ancestry inspection failed")
    cache.ancestor_relations.add(relation)


def _repository_blob_digest(
    repo: Path,
    commit: str,
    relative: str,
    cache: _AnchorCache,
) -> str:
    key = (commit, relative)
    cached = cache.blob_digests.get(key)
    if cached is not None:
        return cached
    if len(cache.blob_digests) >= _MAX_ANCHOR_BLOBS:
        raise HistoryVerificationError("repository evidence anchors exceed the review bound")

    spec = f"{commit}:{relative}"
    object_type = _run_git(repo, "cat-file", "-t", spec, check=False, text=True)
    if object_type.returncode != 0 or object_type.stdout.strip() != "blob":
        raise HistoryVerificationError("repository research memory evidence is not a Git blob")
    size_result = _run_git(repo, "cat-file", "-s", spec, text=True)
    try:
        size = int(size_result.stdout.strip())
    except ValueError as error:
        raise HistoryVerificationError(
            "repository research memory evidence size is invalid"
        ) from error
    if size < 0 or size > _MAX_EVIDENCE_BLOB_BYTES:
        raise HistoryVerificationError(
            "repository research memory evidence exceeds the per-blob review bound"
        )
    if cache.blob_bytes + size > _MAX_ANCHOR_BLOB_BYTES:
        raise HistoryVerificationError(
            "repository research memory evidence exceeds the aggregate review bound"
        )
    data_result = _run_git(repo, "cat-file", "blob", spec)
    assert isinstance(data_result.stdout, bytes)
    if len(data_result.stdout) != size:
        raise HistoryVerificationError(
            "repository research memory evidence changed during object inspection"
        )
    digest = hashlib.sha256(data_result.stdout).hexdigest()
    cache.blob_digests[key] = digest
    cache.blob_bytes += size
    return digest


def _memory_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise HistoryVerificationError("research memory contains a duplicate object key")
        value[key] = item
    return value


def _reject_json_constant(_value: str) -> object:
    raise HistoryVerificationError("research memory contains a non-finite number")


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (RecursionError, TypeError, ValueError) as error:
        raise HistoryVerificationError(
            "research memory cannot be serialized canonically"
        ) from error


def _memory_identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise HistoryVerificationError(f"research memory {label} is invalid")
    return value


def _memory_datetime(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise HistoryVerificationError(f"research memory {label} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise HistoryVerificationError(f"research memory {label} is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise HistoryVerificationError(f"research memory {label} must be timezone-aware")
    canonical = parsed.isoformat()
    if canonical.endswith("+00:00"):
        canonical = canonical[:-6] + "Z"
    if canonical != value:
        raise HistoryVerificationError(f"research memory {label} is not canonical")
    return parsed


def _reject_sensitive_memory_keys(payload: dict[str, object]) -> None:
    pending: list[object] = [payload]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            for key, item in value.items():
                normalized = key.casefold()
                is_reference = normalized.endswith(("_ref", "_reference", "_hash"))
                if not is_reference and any(
                    term in normalized for term in _SENSITIVE_MEMORY_KEY_TERMS
                ):
                    raise HistoryVerificationError(
                        "research memory payload contains a sensitive field"
                    )
                pending.append(item)
        elif isinstance(value, list):
            pending.extend(value)


def _verify_memory_actor(value: object) -> None:
    if not isinstance(value, dict) or set(value) != _MEMORY_ACTOR_FIELDS:
        raise HistoryVerificationError("research memory actor is invalid")
    if not isinstance(value["kind"], str) or value["kind"] not in _MEMORY_ACTOR_KINDS:
        raise HistoryVerificationError("research memory actor kind is invalid")
    _memory_identifier(value["actor_id"], "actor ID")


def _verify_memory_evidence(
    value: object,
    repo: Path,
    containing_commit: str,
    anchor_cache: _AnchorCache,
) -> None:
    if not isinstance(value, list):
        raise HistoryVerificationError("research memory evidence is invalid")
    for evidence in value:
        if not isinstance(evidence, dict) or set(evidence) != _MEMORY_EVIDENCE_FIELDS:
            raise HistoryVerificationError("research memory evidence item is invalid")
        if not isinstance(evidence["role"], str) or evidence["role"] not in _MEMORY_EVIDENCE_ROLES:
            raise HistoryVerificationError("research memory evidence role is invalid")
        uri = evidence["uri"]
        media_type = evidence["media_type"]
        sha256 = evidence["sha256"]
        git_commit = evidence["git_commit"]
        access = evidence["access"]
        label_access = evidence["label_access"]
        if not isinstance(uri, str) or not uri:
            raise HistoryVerificationError("research memory evidence URI is invalid")
        if not isinstance(media_type, str) or not media_type:
            raise HistoryVerificationError("research memory evidence media type is invalid")
        if sha256 is not None and (
            not isinstance(sha256, str) or _SHA256.fullmatch(sha256) is None
        ):
            raise HistoryVerificationError("research memory evidence hash is invalid")
        if git_commit is not None and (
            not isinstance(git_commit, str) or _OID.fullmatch(git_commit) is None
        ):
            raise HistoryVerificationError("research memory evidence commit is invalid")
        if (
            not isinstance(access, str)
            or access not in _MEMORY_ACCESS_CLASSES
            or not isinstance(label_access, str)
            or label_access not in _MEMORY_LABEL_ACCESS
        ):
            raise HistoryVerificationError("research memory evidence access is invalid")
        try:
            parsed = urlsplit(uri)
            hostname = parsed.hostname
            username = parsed.username
            password = parsed.password
        except ValueError as error:
            raise HistoryVerificationError("research memory evidence URI is invalid") from error
        if parsed.scheme:
            if parsed.scheme != "https" or not hostname:
                raise HistoryVerificationError("external research memory evidence must use HTTPS")
            if username is not None or password is not None or "?" in uri or "#" in uri:
                raise HistoryVerificationError("external research memory evidence URI is unsafe")
            if sha256 is None:
                raise HistoryVerificationError("external research memory evidence lacks a hash")
            if git_commit is not None:
                raise HistoryVerificationError(
                    "external research memory evidence must not include a Git commit"
                )
        else:
            pure = PurePosixPath(uri)
            if pure.is_absolute() or ".." in pure.parts:
                raise HistoryVerificationError("repository research memory evidence path is unsafe")
            if git_commit is None:
                raise HistoryVerificationError("repository research memory evidence lacks a commit")
            assert isinstance(git_commit, str)
            _verify_anchor_commit(
                repo,
                git_commit,
                containing_commit,
                anchor_cache,
                label="repository research memory evidence commit",
            )
            digest = _repository_blob_digest(repo, git_commit, uri, anchor_cache)
            if sha256 is not None and digest != sha256:
                raise HistoryVerificationError("repository research memory evidence hash mismatch")
        if sha256 is None and git_commit is None:
            raise HistoryVerificationError("research memory evidence lacks an anchor")
        if access == "public" and label_access == "sealed_heldout":
            raise HistoryVerificationError("sealed held-out research memory evidence is public")


def _verify_memory_bytes(
    data: bytes,
    repo: Path,
    containing_commit: str,
    anchor_cache: _AnchorCache,
) -> None:
    if b"\r" in data:
        raise HistoryVerificationError("research memory must use exact LF framing")
    if data and not data.endswith(b"\n"):
        raise HistoryVerificationError("nonempty research memory must end with one LF")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise HistoryVerificationError("research memory is not valid UTF-8") from error

    previous_hash = _MEMORY_GENESIS_HASH
    event_ids: set[str] = set()
    inbar_identity_started = False
    lines = text[:-1].split("\n") if text else []
    for expected_sequence, line in enumerate(lines):
        if not line:
            raise HistoryVerificationError("research memory contains a blank record")
        try:
            record = json.loads(
                line,
                object_pairs_hook=_memory_object,
                parse_constant=_reject_json_constant,
            )
        except HistoryVerificationError:
            raise
        except (json.JSONDecodeError, RecursionError, TypeError, ValueError) as error:
            raise HistoryVerificationError("research memory contains invalid JSON") from error
        if not isinstance(record, dict) or set(record) != _MEMORY_FIELDS:
            raise HistoryVerificationError("research memory record fields are invalid")
        if _canonical_json(record) != line.encode("utf-8"):
            raise HistoryVerificationError("research memory record is not canonical JSON")

        sequence = record["sequence"]
        if type(sequence) is not int or sequence != expected_sequence:
            raise HistoryVerificationError("research memory sequence is not contiguous")
        schema_version = record["schema_version"]
        mission_id = record["mission_id"]
        if not isinstance(schema_version, str) or not isinstance(mission_id, str):
            raise HistoryVerificationError("research memory identity fields are invalid")
        identity = (schema_version, mission_id)
        if identity not in _MEMORY_IDENTITIES:
            raise HistoryVerificationError("research memory schema and mission identity disagree")
        if mission_id == "inbar":
            inbar_identity_started = True
        elif inbar_identity_started:
            raise HistoryVerificationError("legacy memory identity resumed after Inbar")

        event_id = _memory_identifier(record["event_id"], "event ID")
        if event_id in event_ids:
            raise HistoryVerificationError("research memory event IDs are not unique")
        stage = record["stage"]
        summary = record["summary"]
        if not isinstance(stage, str) or not stage:
            raise HistoryVerificationError("research memory stage is invalid")
        if not isinstance(summary, str) or not summary:
            raise HistoryVerificationError("research memory summary is invalid")
        epistemic_phase = record["epistemic_phase"]
        status = record["status"]
        access = record["access"]
        if not isinstance(epistemic_phase, str) or epistemic_phase not in _MEMORY_EPISTEMIC_PHASES:
            raise HistoryVerificationError("research memory epistemic phase is invalid")
        if not isinstance(status, str) or status not in _MEMORY_STATUSES:
            raise HistoryVerificationError("research memory status is invalid")
        if not isinstance(access, str) or access not in _MEMORY_ACCESS_CLASSES:
            raise HistoryVerificationError("research memory access is invalid")
        _verify_memory_actor(record["actor"])
        occurred_at = _memory_datetime(record["occurred_at"], "occurrence timestamp")
        recorded_at = _memory_datetime(record["recorded_at"], "recording timestamp")
        if recorded_at < occurred_at:
            raise HistoryVerificationError("research memory was recorded before it occurred")
        source_commit = record["source_commit"]
        if not isinstance(source_commit, str) or _OID.fullmatch(source_commit) is None:
            raise HistoryVerificationError("research memory source commit is invalid")
        _verify_anchor_commit(
            repo,
            source_commit,
            containing_commit,
            anchor_cache,
            label="research memory source commit",
        )
        manual_minutes = record["manual_minutes"]
        if (
            type(manual_minutes) is not float
            or not math.isfinite(manual_minutes)
            or manual_minutes < 0.0
        ):
            raise HistoryVerificationError("research memory manual minutes are invalid")
        cost_usd = record["cost_usd"]
        if not isinstance(cost_usd, str) or _MEMORY_COST.fullmatch(cost_usd) is None:
            raise HistoryVerificationError("research memory cost is invalid")
        recurrence_key = record["recurrence_key"]
        if recurrence_key is not None:
            _memory_identifier(recurrence_key, "recurrence key")
        engine_requirement = record["engine_requirement"]
        if engine_requirement is not None and not isinstance(engine_requirement, str):
            raise HistoryVerificationError("research memory engine requirement is invalid")
        claimed_previous = record["previous_event_hash"]
        claimed_hash = record["event_hash"]
        if (
            not isinstance(claimed_previous, str)
            or _SHA256.fullmatch(claimed_previous) is None
            or claimed_previous != previous_hash
        ):
            raise HistoryVerificationError("research memory predecessor hash mismatch")
        if not isinstance(claimed_hash, str) or _SHA256.fullmatch(claimed_hash) is None:
            raise HistoryVerificationError("research memory event hash is invalid")

        payload = record["payload"]
        event_type = record["event_type"]
        if (
            not isinstance(payload, dict)
            or not isinstance(event_type, str)
            or event_type not in _REQUIRED_PAYLOAD_FIELDS
        ):
            raise HistoryVerificationError("research memory event payload is invalid")
        if not _REQUIRED_PAYLOAD_FIELDS[event_type].issubset(payload):
            raise HistoryVerificationError("research memory event payload is incomplete")
        _reject_sensitive_memory_keys(payload)
        _verify_memory_evidence(record["evidence"], repo, containing_commit, anchor_cache)
        if event_type == "manual_work" and recurrence_key is None:
            raise HistoryVerificationError("research memory manual work lacks recurrence")
        links = record["links"]
        if not isinstance(links, dict):
            raise HistoryVerificationError("research memory links are invalid")
        for link_name, target in links.items():
            _memory_identifier(link_name, "link name")
            if _memory_identifier(target, "link target") not in event_ids:
                raise HistoryVerificationError("research memory link does not reference the past")
        correction = record["corrects_event_id"]
        if correction is not None and (
            _memory_identifier(correction, "correction target") not in event_ids
        ):
            raise HistoryVerificationError("research memory correction does not reference the past")
        if (event_type == "correction") != (correction is not None):
            raise HistoryVerificationError("research memory correction contract is invalid")

        body = dict(record)
        body.pop("event_hash")
        computed_hash = hashlib.sha256(_canonical_json(body)).hexdigest()
        if computed_hash != claimed_hash:
            raise HistoryVerificationError("research memory event hash mismatch")
        event_ids.add(event_id)
        previous_hash = claimed_hash


def _memory_blob(
    repo: Path,
    commit: str,
    cache: dict[str, bytes],
    anchor_cache: _AnchorCache,
) -> bytes:
    if commit in cache:
        return cache[commit]
    spec = f"{commit}:{_MEMORY_PATH}"
    object_type = _run_git(repo, "cat-file", "-t", spec, text=True)
    if object_type.stdout.strip() != "blob":
        raise HistoryVerificationError("research memory is not a Git blob")
    size_result = _run_git(repo, "cat-file", "-s", spec, text=True)
    try:
        size = int(size_result.stdout.strip())
    except ValueError as error:
        raise HistoryVerificationError("research memory size is invalid") from error
    if size < 0 or size > _MAX_MEMORY_BYTES:
        raise HistoryVerificationError("research memory exceeds the history input bound")
    data_result = _run_git(repo, "cat-file", "blob", spec)
    assert isinstance(data_result.stdout, bytes)
    if len(data_result.stdout) != size:
        raise HistoryVerificationError("research memory changed during object inspection")
    _verify_memory_bytes(data_result.stdout, repo, commit, anchor_cache)
    cache[commit] = data_result.stdout
    return data_result.stdout


def _required_blob(repo: Path, commit: str, relative: str) -> bytes:
    spec = f"{commit}:{relative}"
    object_type = _run_git(repo, "cat-file", "-t", spec, check=False, text=True)
    if object_type.returncode != 0 or object_type.stdout.strip() != "blob":
        raise HistoryVerificationError(f"required bootstrap artifact is not a blob: {relative}")
    size_result = _run_git(repo, "cat-file", "-s", spec, text=True)
    try:
        size = int(size_result.stdout.strip())
    except ValueError as error:
        raise HistoryVerificationError("required bootstrap artifact size is invalid") from error
    if size < 0 or size > _MAX_MEMORY_BYTES:
        raise HistoryVerificationError("required bootstrap artifact exceeds the input bound")
    data_result = _run_git(repo, "cat-file", "blob", spec)
    assert isinstance(data_result.stdout, bytes)
    if len(data_result.stdout) != size:
        raise HistoryVerificationError("required bootstrap artifact changed during inspection")
    return data_result.stdout


def _bootstrap_appended_records(prefix: bytes, final: bytes) -> list[dict[str, object]]:
    suffix = final[len(prefix) :]
    try:
        lines = suffix.decode("utf-8").splitlines()
        records = [json.loads(line, object_pairs_hook=_memory_object) for line in lines]
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        TypeError,
        ValueError,
    ) as error:
        raise HistoryVerificationError("bootstrap final memory suffix is invalid") from error
    if not records or any(not isinstance(record, dict) for record in records):
        raise HistoryVerificationError("bootstrap final memory suffix has no records")
    return records


def _bootstrap_recovery_evidence_roles(
    record: dict[str, object],
    implementation: str,
) -> frozenset[str]:
    evidence = record.get("evidence")
    if not isinstance(evidence, list):
        raise HistoryVerificationError("bootstrap recovery evidence is invalid")
    roles: set[str] = set()
    for item in evidence:
        if not isinstance(item, dict):
            raise HistoryVerificationError("bootstrap recovery evidence is invalid")
        uri = item.get("uri")
        role = item.get("role")
        git_commit = item.get("git_commit")
        sha256 = item.get("sha256")
        if not isinstance(uri, str) or not isinstance(role, str):
            raise HistoryVerificationError("bootstrap recovery evidence is invalid")
        if not urlsplit(uri).scheme:
            if git_commit != implementation or not isinstance(sha256, str):
                raise HistoryVerificationError(
                    "bootstrap repository evidence must bind the implementation commit"
                )
            roles.add(role)
    return frozenset(roles)


def _verify_bootstrap_recovery_records(
    records: list[dict[str, object]],
    implementation: str,
) -> None:
    checkpoint: dict[str, object] | None = None
    handoff: dict[str, object] | None = None
    for record in records:
        if record.get("source_commit") != implementation:
            raise HistoryVerificationError(
                "bootstrap final records must bind the implementation commit"
            )
        _bootstrap_recovery_evidence_roles(record, implementation)
        payload = record.get("payload")
        if not isinstance(payload, dict):
            raise HistoryVerificationError("bootstrap final record payload is invalid")
        contract = payload.get("handoff_contract")
        if contract == _BOOTSTRAP_CHECKPOINT_CONTRACT:
            if checkpoint is not None:
                raise HistoryVerificationError("bootstrap recovery checkpoint is not unique")
            checkpoint = record
        elif contract == _BOOTSTRAP_HANDOFF_CONTRACT:
            if handoff is not None:
                raise HistoryVerificationError("bootstrap recovery handoff is not unique")
            handoff = record

    if checkpoint is None or handoff is None:
        raise HistoryVerificationError("bootstrap final memory lacks the versioned recovery pair")
    checkpoint_payload = checkpoint["payload"]
    assert isinstance(checkpoint_payload, dict)
    if (
        checkpoint.get("event_type") != "execution"
        or checkpoint.get("status") != "pass"
        or checkpoint.get("stage") != "mission-handoff"
        or checkpoint_payload.get("implementation_commit") != implementation
        or not {"source", "verifier"}
        <= _bootstrap_recovery_evidence_roles(checkpoint, implementation)
    ):
        raise HistoryVerificationError(
            "bootstrap recovery checkpoint does not bind the implementation commit"
        )
    handoff_payload = handoff["payload"]
    links = handoff.get("links")
    if (
        handoff is not records[-1]
        or handoff.get("event_type") != "handoff"
        or handoff.get("status") != "blocked"
        or handoff.get("stage") != "mission-handoff"
        or not isinstance(links, dict)
        or links.get("checkpoint") != checkpoint.get("event_id")
        or not {"source"} <= _bootstrap_recovery_evidence_roles(handoff, implementation)
        or not isinstance(handoff_payload, dict)
    ):
        raise HistoryVerificationError(
            "bootstrap recovery handoff does not bind the implementation checkpoint"
        )


def _changed_paths(repo: Path, parent: str, commit: str) -> frozenset[str]:
    result = _run_git(
        repo,
        "diff",
        "--no-ext-diff",
        "--no-renames",
        "--name-only",
        "-z",
        parent,
        commit,
        "--",
    )
    assert isinstance(result.stdout, bytes)
    paths: list[str] = []
    for raw_path in result.stdout.split(b"\0"):
        if not raw_path:
            continue
        try:
            paths.append(raw_path.decode("utf-8"))
        except UnicodeDecodeError as error:
            raise HistoryVerificationError("bootstrap change path is not valid UTF-8") from error
    if len(paths) != len(set(paths)):
        raise HistoryVerificationError("bootstrap change paths are not unique")
    return frozenset(paths)


def _verify_bootstrap_ceremony(
    repo: Path,
    base: str,
    rows: list[list[str]],
    memory_cache: dict[str, bytes],
    anchor_cache: _AnchorCache,
) -> None:
    if len(rows) != 2:
        raise HistoryVerificationError("one-time CI bootstrap requires exactly two commits")
    implementation_row, final_row = rows
    implementation = _validate_oid(implementation_row[0], "bootstrap implementation commit")
    final = _validate_oid(final_row[0], "bootstrap final commit")
    if implementation_row[1:] != [base] or final_row[1:] != [implementation]:
        raise HistoryVerificationError("one-time CI bootstrap must be a two-commit linear history")

    implementation_paths = _changed_paths(repo, base, implementation)
    if not implementation_paths.issuperset(_BOOTSTRAP_REQUIRED_IMPLEMENTATION_PATHS):
        raise HistoryVerificationError("bootstrap implementation commit lacks required CI policy")
    if implementation_paths & _BOOTSTRAP_FINAL_PATHS:
        raise HistoryVerificationError("bootstrap implementation commit changed memory or handoff")
    if _memory_blob(repo, implementation, memory_cache, anchor_cache) != _memory_blob(
        repo, base, memory_cache, anchor_cache
    ):
        raise HistoryVerificationError("bootstrap implementation commit changed research memory")
    if _required_blob(repo, implementation, _HANDOFF_PATH) != _required_blob(
        repo, base, _HANDOFF_PATH
    ):
        raise HistoryVerificationError("bootstrap implementation commit changed the handoff")

    final_paths = _changed_paths(repo, implementation, final)
    if final_paths != _BOOTSTRAP_FINAL_PATHS:
        raise HistoryVerificationError("bootstrap final commit must change only memory and handoff")
    implementation_memory = _memory_blob(repo, implementation, memory_cache, anchor_cache)
    final_memory = _memory_blob(repo, final, memory_cache, anchor_cache)
    if final_memory == implementation_memory or not final_memory.startswith(implementation_memory):
        raise HistoryVerificationError(
            "bootstrap final commit must strictly append research memory"
        )
    _verify_bootstrap_recovery_records(
        _bootstrap_appended_records(implementation_memory, final_memory),
        implementation,
    )
    if _required_blob(repo, final, _HANDOFF_PATH) == _required_blob(
        repo, implementation, _HANDOFF_PATH
    ):
        raise HistoryVerificationError("bootstrap final commit must update the handoff")


def _forbidden_path(path: str) -> bool:
    forbidden_roots = ("data/raw", "data/derived", ".local")
    folded = path.casefold()
    return (
        folded in forbidden_roots
        or folded.startswith(tuple(f"{root}/" for root in forbidden_roots))
        or folded.endswith(".ed25519")
    )


def _verify_tree(repo: Path, commit: str) -> None:
    result = _run_git(repo, "ls-tree", "-r", "-z", commit)
    assert isinstance(result.stdout, bytes)
    for encoded in result.stdout.split(b"\0"):
        if not encoded:
            continue
        metadata, separator, raw_path = encoded.partition(b"\t")
        fields = metadata.split()
        if separator != b"\t" or len(fields) != 3:
            raise HistoryVerificationError("Git tree entry is malformed")
        mode, object_type, object_id = fields
        if mode not in {b"100644", b"100755"} or object_type != b"blob":
            raise HistoryVerificationError(
                "Git tree contains a symlink, submodule, or special entry"
            )
        try:
            path = raw_path.decode("utf-8")
            object_id_text = object_id.decode("ascii")
        except UnicodeDecodeError as error:
            raise HistoryVerificationError(
                "Git tree path or identity is not canonical text"
            ) from error
        pure = PurePosixPath(path)
        if (
            not path
            or pure.is_absolute()
            or ".." in pure.parts
            or pure.as_posix() != path
            or _OID.fullmatch(object_id_text) is None
        ):
            raise HistoryVerificationError("Git tree contains an unsafe path or object identity")
        if _forbidden_path(path):
            raise HistoryVerificationError(f"forbidden tracked path exists in commit {commit}")
        if pure.name.casefold() == ".gitattributes":
            raise HistoryVerificationError(f"tracked Git attributes exist in commit {commit}")
        if _CREDENTIAL_RE.search(path) is not None:
            raise HistoryVerificationError(
                f"credential signature detected in path at commit {commit}"
            )

    scan = _run_git(
        repo,
        "grep",
        "-q",
        "-E",
        _CREDENTIAL_PATTERN,
        commit,
        "--",
        check=False,
    )
    if scan.returncode == 0:
        raise HistoryVerificationError(f"credential signature detected in commit {commit}")
    if scan.returncode != 1:
        raise HistoryVerificationError(f"credential scanner failed for commit {commit}")


def _verify_commit_object(repo: Path, commit: str) -> None:
    size_result = _run_git(repo, "cat-file", "-s", commit, text=True)
    try:
        size = int(size_result.stdout.strip())
    except ValueError as error:
        raise HistoryVerificationError("raw commit object size is invalid") from error
    if size < 0 or size > _MAX_COMMIT_BYTES:
        raise HistoryVerificationError("raw commit object exceeds the history input bound")
    raw_commit = _run_git(repo, "cat-file", "commit", commit)
    assert isinstance(raw_commit.stdout, bytes)
    if len(raw_commit.stdout) != size:
        raise HistoryVerificationError("raw commit object changed during inspection")
    if _CREDENTIAL_BYTES_RE.search(raw_commit.stdout) is not None:
        raise HistoryVerificationError(
            f"credential signature detected in commit metadata at commit {commit}"
        )


def _verify_protected_policy_edge(repo: Path, range_base: str, parent: str, commit: str) -> None:
    if range_base == _POLICY_BOOTSTRAP_BASE and parent == _POLICY_BOOTSTRAP_BASE:
        return
    changed = _run_git(
        repo,
        "diff",
        "--quiet",
        parent,
        commit,
        "--",
        *_PROTECTED_POLICY_ROOTS,
        check=False,
    )
    if changed.returncode == 1:
        raise HistoryVerificationError(f"protected CI policy changed across {parent}..{commit}")
    if changed.returncode != 0:
        raise HistoryVerificationError(
            f"protected CI policy comparison failed across {parent}..{commit}"
        )


def verify_history(repo: Path, base: str, head: str) -> tuple[int, int]:
    root = repo.resolve(strict=True)
    _verify_commit(root, base, "base")
    _verify_commit(root, head, "head")
    ancestry = _run_git(root, "merge-base", "--is-ancestor", base, head, check=False)
    if ancestry.returncode != 0:
        raise HistoryVerificationError("base is not an ancestor of head")
    graph = _run_git(
        root, "rev-list", "--reverse", "--topo-order", "--parents", f"{base}..{head}", text=True
    )
    assert isinstance(graph.stdout, str)
    rows = [line.split() for line in graph.stdout.splitlines() if line]
    if not rows or len(rows) > _MAX_COMMITS:
        raise HistoryVerificationError(
            "candidate commit count is empty or exceeds the review bound"
        )
    memory_cache: dict[str, bytes] = {}
    anchor_cache = _AnchorCache()
    if base == _POLICY_BOOTSTRAP_BASE:
        _verify_bootstrap_ceremony(root, base, rows, memory_cache, anchor_cache)
    edge_count = 0
    for row in rows:
        commit = _validate_oid(row[0], "candidate commit")
        parents = tuple(_validate_oid(parent, "candidate parent") for parent in row[1:])
        if not parents:
            raise HistoryVerificationError("candidate history contains an unparented commit")
        _verify_commit_object(root, commit)
        _verify_tree(root, commit)
        current_memory = _memory_blob(root, commit, memory_cache, anchor_cache)
        for parent in parents:
            _verify_protected_policy_edge(root, base, parent, commit)
            parent_memory = _memory_blob(root, parent, memory_cache, anchor_cache)
            if not current_memory.startswith(parent_memory):
                raise HistoryVerificationError(
                    f"research memory is not append-only across {parent}..{commit}"
                )
            whitespace = _run_git(root, "diff", "--check", parent, commit, "--", check=False)
            if whitespace.returncode != 0:
                raise HistoryVerificationError(
                    f"whitespace policy failed across {parent}..{commit}"
                )
            edge_count += 1
    return len(rows), edge_count


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        commits, edges = verify_history(arguments.repo, arguments.base, arguments.head)
    except (HistoryVerificationError, OSError) as error:
        print(f"HISTORY_VERIFICATION_FAILED: {error}", file=sys.stderr)
        return 1
    print(f"HISTORY_VERIFIED commits={commits} edges={edges}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
