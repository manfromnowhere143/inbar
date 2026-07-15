"""Leakage-safe ingestion for the public NASA ADAPT electrical testbed dataset."""

from __future__ import annotations

import csv
import json
import math
import os
import re
import secrets
import shutil
import ssl
import stat
import tempfile
import urllib.request
import zipfile
from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal, Self, TypeVar
from urllib.parse import urlsplit

import certifi
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from fieldtrue.canonical import (
    atomic_write,
    canonical_json,
    canonical_json_pretty,
    read_json,
    sha256_file,
    sha256_value,
)
from fieldtrue.domain import (
    ArtifactRef,
    EvidenceBundle,
    EvidenceItem,
    Identifier,
    Modality,
    Sha256,
    TruthRecord,
)

_KNOWN_ROW_TYPES = {
    "ExperimentControl",
    "SensorData",
    "AntagonistData",
    "UserCommand",
    "AntagonistCommand",
    "FaultInject",
}
_FORBIDDEN_EVIDENCE_MARKERS = (
    "ExperimentControl",
    "FaultInject",
    "AntagonistCommand",
    "FaultType",
    "FaultMode",
    "FaultLocation",
    "FaultInjection",
)
_MAX_ARCHIVE_MEMBERS = 1_000
_MAX_ARCHIVE_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
_MAX_MEMBER_COMPRESSION_RATIO = 1_000


def _verified_tls_context() -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=certifi.where())
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


class AdaptResourceLock(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: Identifier
    url: str
    filename: str
    sha256: Sha256
    bytes: int = Field(ge=0)
    media_type: str

    @field_validator("url")
    @classmethod
    def url_is_https_without_credentials(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("resource URL must use HTTPS with a hostname")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("resource URL must not contain credentials")
        return value

    @field_validator("filename")
    @classmethod
    def filename_is_a_basename(cls, value: str) -> str:
        if not value or PurePosixPath(value).name != value or "\\" in value:
            raise ValueError("resource filename must be a plain basename")
        return value


class AdaptDatasetLock(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["fieldtrue.dataset-lock.v1"]
    dataset_id: Identifier
    source_authority: str
    landing_page: str
    license_status: str
    redistribution: str
    resources: tuple[AdaptResourceLock, ...]
    expected_experiment_files: int = Field(gt=0)
    allowed_model_visible_rows: tuple[str, ...]
    truth_only_rows: tuple[str, ...]
    limitations: tuple[str, ...]

    @model_validator(mode="after")
    def resource_ids_are_unique(self) -> Self:
        identifiers = [resource.id for resource in self.resources]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("dataset resource IDs must be unique")
        filenames = [resource.filename for resource in self.resources]
        if len(filenames) != len(set(filenames)):
            raise ValueError("dataset resource filenames must be unique")
        if set(self.allowed_model_visible_rows) != {"AntagonistData", "UserCommand"}:
            raise ValueError("ADAPT model-visible row policy is not the frozen allowlist")
        if set(self.truth_only_rows) != {
            "ExperimentControl",
            "FaultInject",
            "AntagonistCommand",
        }:
            raise ValueError("ADAPT truth-only row policy is not the frozen denylist")
        if "dataset_text.zip" not in filenames:
            raise ValueError("ADAPT lock must contain dataset_text.zip")
        return self


class ResourceReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    resource_id: Identifier
    filename: str
    sha256: Sha256
    bytes: int = Field(ge=0)
    verified: bool


class AdaptFileCoverage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    filename: str
    raw_sha256: Sha256
    experiment_id: Identifier
    sensor_count: int
    telemetry_rows: int
    user_command_rows: int
    antagonist_command_rows: int
    fault_injection_rows: int
    nonempty_rows: int
    row_counts: dict[str, int]


class AdaptCoverageReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["fieldtrue.adapt-coverage.v1"] = "fieldtrue.adapt-coverage.v1"
    expected_files: int
    discovered_files: int
    parsed_files: int
    exact_file_coverage: bool
    total_telemetry_rows: int
    total_user_command_rows: int
    total_fault_injection_rows: int
    files: tuple[AdaptFileCoverage, ...]
    leakage_markers_found: tuple[str, ...]


class AdaptIngestionReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["fieldtrue.adapt-ingestion.v1"] = "fieldtrue.adapt-ingestion.v1"
    dataset_id: Identifier
    dataset_lock_content_sha256: Sha256
    resource_receipts: tuple[ResourceReceipt, ...]
    experiment_count: int
    evidence_bundle_count: int
    truth_record_count: int
    evidence_manifest_sha256: Sha256
    truth_manifest_sha256: Sha256
    coverage_report_sha256: Sha256
    truth_separation_passed: bool
    derived_artifact_hashes: tuple[Sha256, ...]


@dataclass(frozen=True)
class AdaptIngestionResult:
    receipt: AdaptIngestionReceipt
    coverage: AdaptCoverageReport
    evidence_manifest_path: Path
    truth_manifest_path: Path
    receipt_path: Path
    coverage_path: Path
    raw_root: Path


@dataclass(frozen=True)
class _ParsedRun:
    experiment_id: str
    metadata: dict[str, tuple[str, ...]]
    sensor_names: tuple[str, ...]
    telemetry_rows: tuple[tuple[str, ...], ...]
    user_commands: tuple[tuple[str, str, str], ...]
    fault_injections: tuple[tuple[str, ...], ...]
    row_counts: Counter[str]
    raw_path: Path
    raw_sha256: str


def load_adapt_lock(path: Path) -> AdaptDatasetLock:
    return AdaptDatasetLock.model_validate(read_json(path))


def _download_resource(resource: AdaptResourceLock, destination: Path) -> ResourceReceipt:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink():
        raise ValueError(f"resource destination must not be a symlink: {destination}")
    if destination.exists() and not stat.S_ISREG(destination.stat().st_mode):
        raise ValueError(f"resource destination must be a regular file: {destination}")
    if not destination.exists():
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", dir=destination.parent
        )
        temporary_path = Path(temporary_name)
        try:
            request = urllib.request.Request(  # noqa: S310 - frozen HTTPS source
                resource.url,
                headers={"User-Agent": "inbar/0.1"},
            )
            with (
                os.fdopen(descriptor, "wb") as output,
                urllib.request.urlopen(  # noqa: S310
                    request,
                    timeout=60,
                    context=_verified_tls_context(),
                ) as response,
            ):
                final_url = urlsplit(response.geturl())
                source_url = urlsplit(resource.url)
                if final_url.scheme != "https" or final_url.hostname != source_url.hostname:
                    raise ValueError("resource redirect crossed the frozen HTTPS authority")
                shutil.copyfileobj(response, output)
                output.flush()
                os.fsync(output.fileno())
            actual_hash = sha256_file(temporary_path)
            actual_bytes = temporary_path.stat().st_size
            if actual_hash != resource.sha256 or actual_bytes != resource.bytes:
                raise ValueError(
                    f"resource integrity mismatch for {resource.id}: "
                    f"sha256={actual_hash}, bytes={actual_bytes}"
                )
            temporary_path.replace(destination)
        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise
    actual_hash = sha256_file(destination)
    actual_bytes = destination.stat().st_size
    if actual_hash != resource.sha256 or actual_bytes != resource.bytes:
        raise ValueError(
            f"resource integrity mismatch for {resource.id}: "
            f"sha256={actual_hash}, bytes={actual_bytes}"
        )
    return ResourceReceipt(
        resource_id=resource.id,
        filename=resource.filename,
        sha256=actual_hash,
        bytes=actual_bytes,
        verified=True,
    )


def fetch_adapt_dataset(
    lock: AdaptDatasetLock,
    raw_root: Path,
) -> tuple[ResourceReceipt, ...]:
    return tuple(
        _download_resource(resource, raw_root / resource.filename) for resource in lock.resources
    )


def _safe_extract_zip(archive_path: Path, destination: Path) -> None:
    temporary = destination.parent / f".{destination.name}.extracting"
    if temporary.exists():
        shutil.rmtree(temporary)
    temporary.mkdir(parents=True)
    try:
        with zipfile.ZipFile(archive_path) as archive:
            members = archive.infolist()
            if len(members) > _MAX_ARCHIVE_MEMBERS:
                raise ValueError("ZIP archive exceeds the member-count limit")
            if sum(member.file_size for member in members) > _MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                raise ValueError("ZIP archive exceeds the uncompressed-size limit")
            seen_paths: set[PurePosixPath] = set()
            for member in members:
                member_path = PurePosixPath(member.filename)
                mode = member.external_attr >> 16
                file_type = stat.S_IFMT(mode)
                if (
                    member_path.is_absolute()
                    or ".." in member_path.parts
                    or member_path in seen_paths
                    or file_type not in (0, stat.S_IFREG, stat.S_IFDIR)
                    or member.flag_bits & 0x1
                    or (
                        member.file_size > 0
                        and member.file_size / max(member.compress_size, 1)
                        > _MAX_MEMBER_COMPRESSION_RATIO
                    )
                ):
                    raise ValueError(f"unsafe ZIP member: {member.filename}")
                seen_paths.add(member_path)
                target = temporary.joinpath(*member_path.parts)
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
        if destination.exists():
            shutil.rmtree(destination)
        temporary.replace(destination)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def extract_adapt_text_archive(raw_root: Path) -> Path:
    archive = raw_root / "dataset_text.zip"
    destination = raw_root / "extracted"
    _safe_extract_zip(archive, destination)
    dataset_directory = destination / "dataset_text"
    if not dataset_directory.is_dir():
        raise ValueError("ADAPT archive lacks dataset_text directory")
    return dataset_directory


def _metadata_fields(row: list[str]) -> dict[str, tuple[str, ...]]:
    values: dict[str, list[str]] = defaultdict(list)
    for cell in row[2:]:
        cell = cell.strip()
        if not cell:
            continue
        if "=" not in cell:
            raise ValueError(f"unparseable ExperimentControl field: {cell!r}")
        key, value = (part.strip().strip('"') for part in cell.split("=", 1))
        values[key].append(value.replace('""', '"'))
    return {key: tuple(items) for key, items in values.items()}


def _parse_adapt_file(path: Path) -> _ParsedRun:
    parsed_rows: list[list[str]] = []
    with path.open(newline="", encoding="cp1252") as handle:
        for row in csv.reader(handle, delimiter="\t"):
            while row and not row[-1]:
                row.pop()
            if row:
                parsed_rows.append(row)
    unknown = sorted({row[0] for row in parsed_rows} - _KNOWN_ROW_TYPES)
    if unknown:
        raise ValueError(f"unknown row types in {path.name}: {unknown}")
    controls = [row for row in parsed_rows if row[0] == "ExperimentControl"]
    sensor_headers = [row for row in parsed_rows if row[0] == "SensorData"]
    if len(controls) != 1 or len(sensor_headers) != 1:
        raise ValueError(f"{path.name} requires exactly one control and sensor header")
    control = controls[0]
    if len(control) < 3:
        raise ValueError(f"{path.name} has a truncated ExperimentControl row")
    experiment_id = control[1]
    expected_match = re.fullmatch(r"Exp_(\d+)_comp3_pb\.txt", path.name)
    if expected_match is None or expected_match.group(1) != experiment_id:
        raise ValueError(f"experiment ID/file mismatch in {path.name}")
    header = sensor_headers[0]
    if len(header) < 3 or header[1] != "Time":
        raise ValueError(f"invalid sensor header in {path.name}")
    sensor_names = tuple(header[2:])
    if not all(sensor_names) or len(sensor_names) != len(set(sensor_names)):
        raise ValueError(f"sensor names must be nonempty and unique in {path.name}")
    telemetry: list[tuple[str, ...]] = []
    commands: list[tuple[str, str, str]] = []
    injections: list[tuple[str, ...]] = []
    counts: Counter[str] = Counter()
    for row in parsed_rows:
        counts[row[0]] += 1
        if row[0] == "AntagonistData":
            if len(row) != len(header):
                raise ValueError(
                    f"telemetry width mismatch in {path.name}: {len(row)} != {len(header)}"
                )
            try:
                values = [float(value) for value in row[2:]]
            except ValueError as error:
                raise ValueError(f"non-numeric telemetry in {path.name}") from error
            if not all(math.isfinite(value) for value in values):
                raise ValueError(f"non-finite telemetry in {path.name}")
            telemetry.append(tuple(row[1:]))
        elif row[0] == "UserCommand":
            if len(row) != 4:
                raise ValueError(f"user-command width mismatch in {path.name}")
            commands.append((row[1], row[2], row[3]))
        elif row[0] == "FaultInject":
            if len(row) < 8:
                raise ValueError(f"fault-injection row is truncated in {path.name}")
            injections.append(tuple(row[1:]))
    if not telemetry or not commands or not injections:
        raise ValueError(f"{path.name} lacks telemetry, user commands, or fault truth")
    telemetry_times = [row[0] for row in telemetry]
    if telemetry_times != sorted(telemetry_times) or len(telemetry_times) != len(
        set(telemetry_times)
    ):
        raise ValueError(f"telemetry timestamps must be unique and monotonic in {path.name}")
    command_times = [row[0] for row in commands]
    if command_times != sorted(command_times):
        raise ValueError(f"user-command timestamps must be monotonic in {path.name}")
    return _ParsedRun(
        experiment_id=experiment_id,
        metadata=_metadata_fields(control),
        sensor_names=sensor_names,
        telemetry_rows=tuple(telemetry),
        user_commands=tuple(commands),
        fault_injections=tuple(injections),
        row_counts=counts,
        raw_path=path,
        raw_sha256=sha256_file(path),
    )


def _one(metadata: dict[str, tuple[str, ...]], key: str, default: str) -> str:
    values = metadata.get(key, ())
    if not values:
        return default
    if len(values) != 1:
        raise ValueError(f"expected one {key}, got {len(values)}")
    return values[0]


def _write_telemetry(path: Path, run: _ParsedRun) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
            writer.writerow(("timestamp", *run.sensor_names))
            writer.writerows(run.telemetry_rows)
            handle.flush()
            os.fsync(handle.fileno())
        Path(temporary_name).replace(path)
    except Exception:
        Path(temporary_name).unlink(missing_ok=True)
        raise


def _write_commands(path: Path, run: _ParsedRun) -> None:
    content = b"".join(
        canonical_json({"timestamp": timestamp, "command": command, "value": value}) + b"\n"
        for timestamp, command, value in run.user_commands
    )
    atomic_write(path, content)


def _manifest_bytes(models: Sequence[BaseModel]) -> bytes:
    return b"".join(canonical_json(model) + b"\n" for model in models)


def _leakage_markers(paths: list[Path]) -> tuple[str, ...]:
    findings: set[str] = set()
    for path in paths:
        content = path.read_text(encoding="utf-8", errors="strict").casefold()
        for marker in _FORBIDDEN_EVIDENCE_MARKERS:
            if marker.casefold() in content:
                findings.add(f"{path.name}:{marker}")
    return tuple(sorted(findings))


def _verify_resource_receipts(
    lock: AdaptDatasetLock,
    raw_root: Path,
    receipts: tuple[ResourceReceipt, ...],
) -> None:
    expected = {resource.id: resource for resource in lock.resources}
    actual = {receipt.resource_id: receipt for receipt in receipts}
    if len(actual) != len(receipts) or set(actual) != set(expected):
        raise ValueError("resource receipts do not exactly cover the dataset lock")
    for resource_id, resource in expected.items():
        receipt = actual[resource_id]
        if (
            not receipt.verified
            or receipt.filename != resource.filename
            or receipt.sha256 != resource.sha256
            or receipt.bytes != resource.bytes
        ):
            raise ValueError(f"resource receipt does not match lock: {resource_id}")
        path = raw_root / resource.filename
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"locked resource is missing or unsafe: {resource_id}")
        if sha256_file(path) != resource.sha256 or path.stat().st_size != resource.bytes:
            raise ValueError(f"locked resource bytes changed after acquisition: {resource_id}")


def ingest_adapt_dataset(
    lock: AdaptDatasetLock,
    raw_root: Path,
    output_root: Path,
    resource_receipts: tuple[ResourceReceipt, ...],
) -> AdaptIngestionResult:
    _verify_resource_receipts(lock, raw_root, resource_receipts)
    if output_root.exists() and any(output_root.iterdir()):
        raise ValueError("derived output root must be empty before ingestion")
    dataset_directory = extract_adapt_text_archive(raw_root)
    discovered_files = sorted(path for path in dataset_directory.rglob("*") if path.is_file())
    source_files = [
        path
        for path in discovered_files
        if re.fullmatch(r"Exp_\d+_comp3_pb\.txt", path.name) is not None
        and path.parent == dataset_directory
    ]
    if source_files != discovered_files:
        unexpected = [path.relative_to(dataset_directory).as_posix() for path in discovered_files]
        raise ValueError(f"ADAPT archive contains an unexpected file inventory: {unexpected}")
    if len(source_files) != lock.expected_experiment_files:
        raise ValueError(
            f"expected {lock.expected_experiment_files} files, discovered {len(source_files)}"
        )
    runs = [_parse_adapt_file(path) for path in source_files]
    if len({run.experiment_id for run in runs}) != len(runs):
        raise ValueError("duplicate ADAPT experiment IDs")

    evidence_bundles: list[EvidenceBundle] = []
    truth_records: list[TruthRecord] = []
    coverage_files: list[AdaptFileCoverage] = []
    model_visible_paths: list[Path] = []
    derived_hashes: list[str] = []
    source_lineage = tuple(sorted(receipt.sha256 for receipt in resource_receipts))
    for run in runs:
        incident_id = f"adapt-{run.experiment_id}"
        telemetry_relative = Path("evidence") / f"{incident_id}.telemetry.tsv"
        command_relative = Path("evidence") / f"{incident_id}.commands.jsonl"
        telemetry_path = output_root / telemetry_relative
        command_path = output_root / command_relative
        _write_telemetry(telemetry_path, run)
        _write_commands(command_path, run)
        model_visible_paths.extend((telemetry_path, command_path))
        telemetry_hash = sha256_file(telemetry_path)
        command_hash = sha256_file(command_path)
        derived_hashes.extend((telemetry_hash, command_hash))

        mechanism_ids = tuple(
            f"{incident_id}-mechanism-{index}"
            for index, _ in enumerate(run.fault_injections, start=1)
        )
        truth = TruthRecord(
            incident_id=incident_id,
            commitment_nonce=secrets.token_hex(32),
            hardware_family="NASA ADAPT electrical power system",
            hardware_id="NASA Ames ADAPT EPS",
            fault_family=_one(run.metadata, "FaultType", "controlled_fault_injection"),
            mechanism_ids=mechanism_ids,
            cause_authority="NASA ADAPT controlled fault injection",
            verification_method="ExperimentControl metadata plus FaultInject event",
            injection_method=_one(run.metadata, "FaultInjection", "mixed_or_unspecified"),
            injection_times=tuple(injection[0] for injection in run.fault_injections),
            competing_hypothesis_ids=(),
            safe_discriminating_test_ids=(),
            notes=tuple(
                f"fault_{index}:location={injection[1]};mode={injection[3]}"
                for index, injection in enumerate(run.fault_injections, start=1)
            ),
        )
        truth_records.append(truth)
        truth_commitment = sha256_value(truth)
        observed_start = run.telemetry_rows[0][0]
        observed_end = run.telemetry_rows[-1][0]
        evidence_bundles.append(
            EvidenceBundle(
                incident_id=incident_id,
                system_family="NASA ADAPT electrical power system",
                system_id="NASA Ames ADAPT EPS",
                mission_id="nasa-adapt-public-campaign",
                context={},
                evidence=(
                    EvidenceItem(
                        evidence_id=f"{incident_id}-telemetry",
                        modality=Modality.TELEMETRY,
                        artifact=ArtifactRef(
                            artifact_id=f"{incident_id}-telemetry-artifact",
                            uri=telemetry_relative.as_posix(),
                            sha256=telemetry_hash,
                            bytes=telemetry_path.stat().st_size,
                            media_type="text/tab-separated-values",
                            source_authority=lock.source_authority,
                            clock_domain=f"{incident_id}-experiment-clock",
                            license_ref="DATA_LICENSES.md#nasa-adapt",
                            lineage_sha256=source_lineage,
                        ),
                        observed_start=observed_start,
                        observed_end=observed_end,
                        description=(
                            "Operator-visible 2 Hz sensor telemetry after antagonist filtering"
                        ),
                    ),
                    EvidenceItem(
                        evidence_id=f"{incident_id}-commands",
                        modality=Modality.COMMAND_LOG,
                        artifact=ArtifactRef(
                            artifact_id=f"{incident_id}-commands-artifact",
                            uri=command_relative.as_posix(),
                            sha256=command_hash,
                            bytes=command_path.stat().st_size,
                            media_type="application/x-ndjson",
                            source_authority=lock.source_authority,
                            clock_domain=f"{incident_id}-experiment-clock",
                            license_ref="DATA_LICENSES.md#nasa-adapt",
                            lineage_sha256=source_lineage,
                        ),
                        observed_start=run.user_commands[0][0],
                        observed_end=run.user_commands[-1][0],
                        description="User-issued commands; antagonist-internal commands excluded",
                    ),
                ),
                truth_commitment=truth_commitment,
            )
        )
        coverage_files.append(
            AdaptFileCoverage(
                filename=run.raw_path.name,
                raw_sha256=run.raw_sha256,
                experiment_id=incident_id,
                sensor_count=len(run.sensor_names),
                telemetry_rows=len(run.telemetry_rows),
                user_command_rows=len(run.user_commands),
                antagonist_command_rows=run.row_counts["AntagonistCommand"],
                fault_injection_rows=len(run.fault_injections),
                nonempty_rows=sum(run.row_counts.values()),
                row_counts=dict(sorted(run.row_counts.items())),
            )
        )

    evidence_manifest_path = output_root / "manifests" / "evidence.jsonl"
    truth_manifest_path = output_root / "truth" / "truth.jsonl"
    evidence_bytes = _manifest_bytes(evidence_bundles)
    truth_bytes = _manifest_bytes(truth_records)
    atomic_write(evidence_manifest_path, evidence_bytes)
    atomic_write(truth_manifest_path, truth_bytes, mode=0o600)
    model_visible_paths.append(evidence_manifest_path)
    leakage = _leakage_markers(model_visible_paths)
    coverage = AdaptCoverageReport(
        expected_files=lock.expected_experiment_files,
        discovered_files=len(source_files),
        parsed_files=len(runs),
        exact_file_coverage=len(runs) == lock.expected_experiment_files,
        total_telemetry_rows=sum(len(run.telemetry_rows) for run in runs),
        total_user_command_rows=sum(len(run.user_commands) for run in runs),
        total_fault_injection_rows=sum(len(run.fault_injections) for run in runs),
        files=tuple(coverage_files),
        leakage_markers_found=leakage,
    )
    coverage_path = output_root / "coverage.json"
    atomic_write(coverage_path, canonical_json_pretty(coverage))
    receipt = AdaptIngestionReceipt(
        dataset_id=lock.dataset_id,
        dataset_lock_content_sha256=sha256_value(lock),
        resource_receipts=resource_receipts,
        experiment_count=len(runs),
        evidence_bundle_count=len(evidence_bundles),
        truth_record_count=len(truth_records),
        evidence_manifest_sha256=sha256_file(evidence_manifest_path),
        truth_manifest_sha256=sha256_file(truth_manifest_path),
        coverage_report_sha256=sha256_file(coverage_path),
        truth_separation_passed=not leakage,
        derived_artifact_hashes=tuple(sorted(derived_hashes)),
    )
    receipt_path = output_root / "ingestion_receipt.json"
    atomic_write(receipt_path, canonical_json_pretty(receipt))
    return AdaptIngestionResult(
        receipt=receipt,
        coverage=coverage,
        evidence_manifest_path=evidence_manifest_path,
        truth_manifest_path=truth_manifest_path,
        receipt_path=receipt_path,
        coverage_path=coverage_path,
        raw_root=raw_root,
    )


ModelT = TypeVar("ModelT", bound=BaseModel)


def load_jsonl_models(path: Path, model: type[ModelT]) -> list[ModelT]:
    records: list[ModelT] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            records.append(model.model_validate_json(line))
        except (ValueError, json.JSONDecodeError) as error:
            raise ValueError(f"invalid {path.name} line {line_number}") from error
    return records
