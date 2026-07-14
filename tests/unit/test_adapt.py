from __future__ import annotations

import hashlib
import io
import json
import os
import zipfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from fieldtrue.adapters.adapt import (
    AdaptDatasetLock,
    AdaptResourceLock,
    ResourceReceipt,
    _download_resource,
    _leakage_markers,
    _one,
    _parse_adapt_file,
    _safe_extract_zip,
    extract_adapt_text_archive,
    fetch_adapt_dataset,
    ingest_adapt_dataset,
    load_adapt_lock,
    load_jsonl_models,
)
from fieldtrue.canonical import sha256_file, sha256_value
from fieldtrue.domain import EvidenceBundle, TruthRecord
from tests.helpers import HASH_A, adapt_text, create_adapt_source


def test_adapt_ingestion_separates_truth_and_binds_every_artifact(tmp_path: Path) -> None:
    raw_root = tmp_path / "raw"
    output_root = tmp_path / "derived"
    lock, receipts = create_adapt_source(raw_root)
    result = ingest_adapt_dataset(lock, raw_root, output_root, receipts)

    evidence = load_jsonl_models(result.evidence_manifest_path, EvidenceBundle)
    truth = load_jsonl_models(result.truth_manifest_path, TruthRecord)
    assert len(evidence) == len(truth) == 1
    assert evidence[0].context == {}
    assert evidence[0].truth_commitment == sha256_value(truth[0])
    assert len(truth[0].commitment_nonce) == 64
    assert result.receipt.dataset_lock_content_sha256 == sha256_value(lock)
    assert result.receipt.truth_separation_passed
    assert result.coverage.files[0].nonempty_rows == sum(
        result.coverage.files[0].row_counts.values()
    )
    assert result.truth_manifest_path.stat().st_mode & 0o777 == 0o600
    visible = result.evidence_manifest_path.read_text().casefold()
    assert "faultinject" not in visible
    assert "faulttype" not in visible
    for item in evidence[0].evidence:
        path = output_root / item.artifact.uri
        assert sha256_file(path) == item.artifact.sha256
        assert set(item.artifact.lineage_sha256) == {receipts[0].sha256}


def test_ingestion_rejects_forged_receipts_and_changed_raw_bytes(tmp_path: Path) -> None:
    raw_root = tmp_path / "raw"
    lock, receipts = create_adapt_source(raw_root)
    forged = (
        ResourceReceipt(
            resource_id=receipts[0].resource_id,
            filename=receipts[0].filename,
            sha256=HASH_A,
            bytes=receipts[0].bytes,
            verified=True,
        ),
    )
    with pytest.raises(ValueError, match="does not match lock"):
        ingest_adapt_dataset(lock, raw_root, tmp_path / "forged", forged)

    (raw_root / "dataset_text.zip").write_bytes(b"changed-after-receipt")
    with pytest.raises(ValueError, match="bytes changed"):
        ingest_adapt_dataset(lock, raw_root, tmp_path / "changed", receipts)


def test_fetch_reuses_only_exact_locked_bytes(tmp_path: Path) -> None:
    lock, receipts = create_adapt_source(tmp_path)
    assert fetch_adapt_dataset(lock, tmp_path) == receipts
    (tmp_path / "dataset_text.zip").write_bytes(b"wrong")
    with pytest.raises(ValueError, match="integrity mismatch"):
        fetch_adapt_dataset(lock, tmp_path)


def test_parser_and_archive_fail_closed(tmp_path: Path) -> None:
    unknown_root = tmp_path / "unknown"
    lock, receipts = create_adapt_source(unknown_root, unknown_row=True)
    with pytest.raises(ValueError, match="unknown row types"):
        ingest_adapt_dataset(lock, unknown_root, tmp_path / "unknown-out", receipts)

    unsafe_root = tmp_path / "unsafe"
    lock, receipts = create_adapt_source(unsafe_root, unsafe_member=True)
    with pytest.raises(ValueError, match="unsafe ZIP member"):
        ingest_adapt_dataset(lock, unsafe_root, tmp_path / "unsafe-out", receipts)


def test_archive_inventory_and_stale_outputs_are_rejected(tmp_path: Path) -> None:
    raw_root = tmp_path / "raw"
    lock, receipts = create_adapt_source(raw_root)
    output_root = tmp_path / "derived"
    output_root.mkdir()
    (output_root / "stale").write_text("old")
    with pytest.raises(ValueError, match="must be empty"):
        ingest_adapt_dataset(lock, raw_root, output_root, receipts)

    archive = raw_root / "dataset_text.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("dataset_text/Exp_001_comp3_pb.txt", adapt_text())
        handle.writestr("dataset_text/unregistered.txt", "extra")
    resource = lock.resources[0].model_copy(
        update={"sha256": sha256_file(archive), "bytes": archive.stat().st_size}
    )
    changed_lock = lock.model_copy(update={"resources": (resource,)})
    changed_receipts = (
        ResourceReceipt(
            resource_id=resource.id,
            filename=resource.filename,
            sha256=resource.sha256,
            bytes=resource.bytes,
            verified=True,
        ),
    )
    with pytest.raises(ValueError, match="unexpected file inventory"):
        ingest_adapt_dataset(
            changed_lock,
            raw_root,
            tmp_path / "inventory-out",
            changed_receipts,
        )


def test_lock_rejects_unsafe_sources_and_weakened_row_policy() -> None:
    base = {
        "id": "dataset-text",
        "url": "https://example.invalid/data.zip",
        "filename": "dataset_text.zip",
        "sha256": HASH_A,
        "bytes": 1,
        "media_type": "application/zip",
    }
    with pytest.raises(ValidationError, match="HTTPS"):
        AdaptResourceLock.model_validate({**base, "url": "file:///etc/hosts"})
    with pytest.raises(ValidationError, match="basename"):
        AdaptResourceLock.model_validate({**base, "filename": "../data.zip"})
    resource = AdaptResourceLock.model_validate(base)
    with pytest.raises(ValidationError, match="frozen allowlist"):
        AdaptDatasetLock(
            schema_version="fieldtrue.dataset-lock.v1",
            dataset_id="bad-policy",
            source_authority="fixture",
            landing_page="https://example.invalid",
            license_status="fixture",
            redistribution="none",
            resources=(resource,),
            expected_experiment_files=1,
            allowed_model_visible_rows=("ExperimentControl",),
            truth_only_rows=("ExperimentControl", "FaultInject", "AntagonistCommand"),
            limitations=(),
        )


def test_lock_and_jsonl_loaders_reject_malformed_inputs(tmp_path: Path) -> None:
    lock_path = tmp_path / "lock.json"
    lock_path.write_text(json.dumps({"not": "a lock"}))
    with pytest.raises(ValidationError):
        load_adapt_lock(lock_path)
    jsonl = tmp_path / "bad.jsonl"
    jsonl.write_text("not-json\n")
    with pytest.raises(ValueError, match="line 1"):
        load_jsonl_models(jsonl, EvidenceBundle)


def test_resource_destination_symlink_is_rejected(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    lock, _ = create_adapt_source(source_root)
    destination = tmp_path / "destination"
    destination.mkdir()
    target = destination / "target"
    target.write_bytes(b"target")
    os.symlink(target, destination / "dataset_text.zip")
    with pytest.raises(ValueError, match="symlink"):
        fetch_adapt_dataset(lock, destination)


class _Response(io.BytesIO):
    def __init__(self, data: bytes, final_url: str) -> None:
        super().__init__(data)
        self._final_url = final_url

    def geturl(self) -> str:
        return self._final_url

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def test_download_verifies_temporary_bytes_before_promotion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = b"frozen-source"
    resource = AdaptResourceLock(
        id="download",
        url="https://source.example/data.bin",
        filename="data.bin",
        sha256=hashlib.sha256(data).hexdigest(),
        bytes=len(data),
        media_type="application/octet-stream",
    )
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *_args, **_kwargs: _Response(data, resource.url),
    )
    destination = tmp_path / resource.filename
    receipt = _download_resource(resource, destination)
    assert receipt.verified
    assert destination.read_bytes() == data

    redirected = resource.model_copy(update={"filename": "redirected.bin"})
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *_args, **_kwargs: _Response(data, "https://attacker.invalid/data.bin"),
    )
    with pytest.raises(ValueError, match="redirect"):
        _download_resource(redirected, tmp_path / redirected.filename)
    assert not (tmp_path / redirected.filename).exists()

    corrupt = resource.model_copy(update={"filename": "corrupt.bin"})
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *_args, **_kwargs: _Response(b"wrong", resource.url),
    )
    with pytest.raises(ValueError, match="integrity mismatch"):
        _download_resource(corrupt, tmp_path / corrupt.filename)
    assert not (tmp_path / corrupt.filename).exists()


def test_archive_limits_and_missing_dataset_directory_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "archive.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("one", "1")
        handle.writestr("two", "2")
    monkeypatch.setattr("fieldtrue.adapters.adapt._MAX_ARCHIVE_MEMBERS", 1)
    with pytest.raises(ValueError, match="member-count"):
        _safe_extract_zip(archive, tmp_path / "members")
    monkeypatch.setattr("fieldtrue.adapters.adapt._MAX_ARCHIVE_MEMBERS", 1000)
    monkeypatch.setattr("fieldtrue.adapters.adapt._MAX_ARCHIVE_UNCOMPRESSED_BYTES", 1)
    with pytest.raises(ValueError, match="uncompressed-size"):
        _safe_extract_zip(archive, tmp_path / "size")
    monkeypatch.setattr(
        "fieldtrue.adapters.adapt._MAX_ARCHIVE_UNCOMPRESSED_BYTES",
        256 * 1024 * 1024,
    )

    raw_root = tmp_path / "missing-directory"
    raw_root.mkdir()
    with zipfile.ZipFile(raw_root / "dataset_text.zip", "w") as handle:
        handle.writestr("wrong/place.txt", "data")
    with pytest.raises(ValueError, match="lacks dataset_text"):
        extract_adapt_text_archive(raw_root)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda text: text.replace("V1\tS1", "V1\tV1"), "sensor names"),
        (lambda text: text.replace("24.0\t1", "NaN\t1"), "non-finite"),
        (lambda text: text.replace("24.0\t1", "word\t1"), "non-numeric"),
        (lambda text: text.replace("\t24.0\t1", "\t24.0"), "telemetry width"),
        (lambda text: text.replace("\tR1_CL\t1", "\tR1_CL"), "user-command width"),
        (lambda text: text.replace("\tSticks open\tAbrupt\tStuck At=0", ""), "truncated"),
        (lambda text: text.replace("SensorData\tTime", "SensorData\tClock"), "sensor header"),
        (lambda text: "\n".join(text.splitlines()[1:]) + "\n", "control and sensor"),
    ],
)
def test_parser_rejects_structural_and_numeric_corruption(
    tmp_path: Path,
    mutation,
    message: str,
) -> None:
    path = tmp_path / "Exp_001_comp3_pb.txt"
    path.write_text(mutation(adapt_text()))
    with pytest.raises(ValueError, match=message):
        _parse_adapt_file(path)


def test_parser_rejects_time_and_identity_mismatch(tmp_path: Path) -> None:
    wrong_id = tmp_path / "Exp_002_comp3_pb.txt"
    wrong_id.write_text(adapt_text("001"))
    with pytest.raises(ValueError, match="ID/file mismatch"):
        _parse_adapt_file(wrong_id)

    duplicate_time = tmp_path / "Exp_001_comp3_pb.txt"
    duplicate_time.write_text(
        adapt_text().replace(
            "2007-01-01 00:00:02 GMT-07:00\t0.0\t0",
            "2007-01-01 00:00:00 GMT-07:00\t0.0\t0",
        )
    )
    with pytest.raises(ValueError, match="unique and monotonic"):
        _parse_adapt_file(duplicate_time)


def test_metadata_and_leakage_helpers_are_fail_closed(tmp_path: Path) -> None:
    assert _one({}, "missing", "default") == "default"
    with pytest.raises(ValueError, match="expected one"):
        _one({"duplicate": ("a", "b")}, "duplicate", "default")
    visible = tmp_path / "visible.json"
    visible.write_text('{"field":"fAuLtTyPe"}')
    assert _leakage_markers([visible]) == ("visible.json:FaultType",)
