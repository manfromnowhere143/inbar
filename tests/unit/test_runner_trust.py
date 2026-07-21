from __future__ import annotations

import hashlib
import http.client
import io
import json
import os
import stat
import subprocess
import tomllib
import zipfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import fieldtrue.runner_trust as trust


class _Response:
    def __init__(self, data: bytes, final_url: str) -> None:
        self._data = data
        self._final_url = final_url

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def geturl(self) -> str:
        return self._final_url

    def read(self, maximum: int) -> bytes:
        return self._data[:maximum]


def _executable_binding(path: Path) -> trust.ExecutableBinding:
    return trust.ExecutableBinding(
        lexical_path=path,
        resolved_path=path,
        sha256="a" * 64,
        size=1,
        mode=0o755,
        owner_uid=os.getuid(),
        owner_gid=os.getgid(),
    )


def _wheel_archive(*entries: tuple[zipfile.ZipInfo | str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for member, payload in entries:
            archive.writestr(member, payload)
    return buffer.getvalue()


def test_locked_runner_closure_is_exact_and_includes_pynacl() -> None:
    lock = tomllib.loads((Path(__file__).parents[2] / "uv.lock").read_text())
    wheels = trust.resolve_locked_wheels(
        lock,
        root_distributions=frozenset({"certifi", "networkx", "pydantic", "pynacl", "pytest"}),
    )
    names = {wheel.distribution for wheel in wheels}

    assert {"cffi", "pycparser", "pynacl", "pytest"}.issubset(names)
    assert len(names) == len(wheels)
    assert all(len(wheel.sha256) == 64 and wheel.size > 0 for wheel in wheels)


def test_locked_runner_rejects_oversized_package_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock = tomllib.loads((Path(__file__).parents[2] / "uv.lock").read_text())
    monkeypatch.setattr(trust, "MAX_LOCK_PACKAGE_ENTRIES", 1)

    with pytest.raises(trust.RunnerTrustError, match="package inventory"):
        trust.resolve_locked_packages(lock, frozenset({"certifi"}))


def test_locked_runner_rejects_oversized_dependency_closure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock = tomllib.loads((Path(__file__).parents[2] / "uv.lock").read_text())
    monkeypatch.setattr(trust, "MAX_LOCKED_DISTRIBUTIONS", 1)

    with pytest.raises(trust.RunnerTrustError, match="distribution count"):
        trust.resolve_locked_packages(lock, frozenset({"certifi", "pytest"}))


def test_locked_runner_rejects_aggregate_wheel_bytes_before_download(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock = tomllib.loads((Path(__file__).parents[2] / "uv.lock").read_text())
    monkeypatch.setattr(trust, "MAX_AUTHENTICATED_WHEEL_SET_BYTES", 1)

    with pytest.raises(trust.RunnerTrustError, match="wheel set byte limit"):
        trust.resolve_locked_wheels(lock, root_distributions=frozenset({"certifi"}))


def test_hostile_artifact_cache_is_rehashed_and_never_executed_as_trust(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = b"authenticated-wheel-bytes"
    digest = hashlib.sha256(data).hexdigest()
    cache_root = tmp_path / "cache"
    namespace = cache_root / "lock"
    namespace.mkdir(parents=True)
    cache_path = namespace / f"{digest}-artifact.whl"
    cache_path.write_bytes(b"hostile-cache-bytes")
    url = "https://files.pythonhosted.org/packages/artifact.whl"
    monkeypatch.setattr(
        trust.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _Response(data, url),
    )

    observed = trust.authenticated_artifact_bytes(
        url=url,
        expected_sha256=digest,
        expected_size=len(data),
        cache_root=cache_root,
        cache_namespace="lock",
    )
    assert observed == data
    assert cache_path.read_bytes() == data

    cache_path.write_bytes(b"stable-hostile-cache")

    def offline(*_args: Any, **_kwargs: Any) -> Any:
        raise OSError("network unavailable")

    monkeypatch.setattr(trust.urllib.request, "urlopen", offline)
    with pytest.raises(
        trust.RunnerAcquisitionError,
        match="acquisition could not be completed",
    ) as caught:
        trust.authenticated_artifact_bytes(
            url=url,
            expected_sha256=digest,
            expected_size=len(data),
            cache_root=cache_root,
            cache_namespace="lock",
        )
    assert not isinstance(caught.value, trust.RunnerTrustError)


@pytest.mark.parametrize(
    "failure",
    [OSError("network unavailable"), TimeoutError("network timed out")],
)
def test_authenticated_artifact_transport_failures_are_acquisition_not_trust(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: OSError,
) -> None:
    def unavailable(*_args: Any, **_kwargs: Any) -> Any:
        raise failure

    monkeypatch.setattr(trust.urllib.request, "urlopen", unavailable)
    with pytest.raises(
        trust.RunnerAcquisitionError,
        match="acquisition could not be completed",
    ) as caught:
        trust.authenticated_artifact_bytes(
            url="https://files.pythonhosted.org/packages/artifact.whl",
            expected_sha256="a" * 64,
            expected_size=1,
            cache_root=tmp_path / "cache",
            cache_namespace="lock",
        )
    assert not isinstance(caught.value, trust.RunnerTrustError)


def test_authenticated_artifact_tls_initialization_failure_is_acquisition_not_trust(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(*_args: Any, **_kwargs: Any) -> Any:
        raise OSError("CA store unavailable")

    monkeypatch.setattr(trust.ssl, "create_default_context", unavailable)
    with pytest.raises(
        trust.RunnerAcquisitionError,
        match="acquisition could not be initialized",
    ) as caught:
        trust.authenticated_artifact_bytes(
            url="https://files.pythonhosted.org/packages/artifact.whl",
            expected_sha256="a" * 64,
            expected_size=1,
            cache_root=tmp_path / "cache",
            cache_namespace="lock",
        )
    assert not isinstance(caught.value, trust.RunnerTrustError)


def test_authenticated_artifact_incomplete_read_is_acquisition_not_trust(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url = "https://files.pythonhosted.org/packages/artifact.whl"
    response = _Response(b"", url)

    def incomplete(_maximum: int) -> bytes:
        raise http.client.IncompleteRead(b"", 1)

    monkeypatch.setattr(response, "read", incomplete)
    monkeypatch.setattr(
        trust.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: response,
    )
    with pytest.raises(
        trust.RunnerAcquisitionError,
        match="acquisition could not be completed",
    ) as caught:
        trust.authenticated_artifact_bytes(
            url=url,
            expected_sha256="a" * 64,
            expected_size=1,
            cache_root=tmp_path / "cache",
            cache_namespace="lock",
        )
    assert not isinstance(caught.value, trust.RunnerTrustError)


def test_cold_github_redirect_is_explicit_and_percent_encoded_name_is_decoded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = b"pinned-python-archive"
    digest = hashlib.sha256(data).hexdigest()
    origin = "https://github.com/releases/python%2Bbuild.tar.gz"
    final = "https://release-assets.githubusercontent.com/asset/python.tar.gz?sig=frozen-hop"
    monkeypatch.setattr(
        trust.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _Response(data, final),
    )

    observed = trust.authenticated_artifact_bytes(
        url=origin,
        expected_sha256=digest,
        expected_size=len(data),
        cache_root=tmp_path / "cache",
        cache_namespace="20260623",
        allowed_redirect_hosts=frozenset({"github.com", "release-assets.githubusercontent.com"}),
        signed_query_redirect_hosts=frozenset({"release-assets.githubusercontent.com"}),
    )
    assert observed == data
    assert (tmp_path / "cache" / "20260623" / f"{digest}-python+build.tar.gz").read_bytes() == data

    with pytest.raises(
        trust.RunnerTrustError,
        match="redirected across authority",
    ) as caught:
        trust.authenticated_artifact_bytes(
            url=origin,
            expected_sha256=digest,
            expected_size=len(data),
            cache_root=tmp_path / "second-cache",
            cache_namespace="20260623",
            allowed_redirect_hosts=frozenset({"github.com"}),
        )
    assert not isinstance(caught.value, trust.RunnerAcquisitionError)


def test_malformed_final_redirect_authority_is_trust_not_acquisition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = b"pinned-artifact"
    origin = "https://files.pythonhosted.org/packages/artifact.whl"
    monkeypatch.setattr(
        trust.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _Response(
            data,
            "https://files.pythonhosted.org:invalid/artifact.whl",
        ),
    )

    with pytest.raises(
        trust.RunnerTrustError,
        match="redirect authority is invalid",
    ) as caught:
        trust.authenticated_artifact_bytes(
            url=origin,
            expected_sha256=hashlib.sha256(data).hexdigest(),
            expected_size=len(data),
            cache_root=tmp_path / "cache",
            cache_namespace="lock",
        )
    assert not isinstance(caught.value, trust.RunnerAcquisitionError)


def test_malformed_redirect_policy_is_rejected_before_warm_cache_return(tmp_path: Path) -> None:
    data = b"warm-cache"
    digest = hashlib.sha256(data).hexdigest()
    cache_root = tmp_path / "cache"
    namespace = cache_root / "lock"
    namespace.mkdir(parents=True)
    (namespace / f"{digest}-artifact.whl").write_bytes(data)

    with pytest.raises(trust.RunnerTrustError, match="redirect policy"):
        trust.authenticated_artifact_bytes(
            url="https://files.pythonhosted.org/artifact.whl",
            expected_sha256=digest,
            expected_size=len(data),
            cache_root=cache_root,
            cache_namespace="lock",
            allowed_redirect_hosts=frozenset({"files.pythonhosted.org"}),
            signed_query_redirect_hosts=frozenset({"unexpected.example"}),
        )


def test_authenticated_artifact_rejects_malformed_url_authority(tmp_path: Path) -> None:
    with pytest.raises(trust.RunnerTrustError, match="URL authority"):
        trust.authenticated_artifact_bytes(
            url="https://[malformed/artifact.whl",
            expected_sha256="a" * 64,
            expected_size=1,
            cache_root=tmp_path / "cache",
            cache_namespace="lock",
        )


def test_authenticated_artifact_rejects_non_private_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(trust, "ensure_private_directory", lambda _path: False)

    with pytest.raises(trust.RunnerTrustError, match="cache is not private"):
        trust.authenticated_artifact_bytes(
            url="https://files.pythonhosted.org/artifact.whl",
            expected_sha256="a" * 64,
            expected_size=1,
            cache_root=tmp_path / "cache",
            cache_namespace="lock",
        )


def test_authenticated_artifact_short_body_is_acquisition_not_trust(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = b"expected-bytes"
    url = "https://files.pythonhosted.org/artifact.whl"
    monkeypatch.setattr(
        trust.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _Response(b"short", url),
    )

    with pytest.raises(
        trust.RunnerAcquisitionError,
        match="acquisition could not be completed",
    ) as caught:
        trust.authenticated_artifact_bytes(
            url=url,
            expected_sha256=hashlib.sha256(expected).hexdigest(),
            expected_size=len(expected),
            cache_root=tmp_path / "cache",
            cache_namespace="lock",
        )
    assert not isinstance(caught.value, trust.RunnerTrustError)


@pytest.mark.parametrize(
    "downloaded",
    [b"x" * len(b"expected-bytes"), b"wrong-size-and-digest"],
)
def test_authenticated_artifact_rejects_oversized_or_wrong_digest_as_trust(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    downloaded: bytes,
) -> None:
    expected = b"expected-bytes"
    digest = hashlib.sha256(expected).hexdigest()
    url = "https://files.pythonhosted.org/artifact.whl"
    monkeypatch.setattr(
        trust.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _Response(downloaded, url),
    )

    with pytest.raises(trust.RunnerTrustError, match="frozen digest") as caught:
        trust.authenticated_artifact_bytes(
            url=url,
            expected_sha256=digest,
            expected_size=len(expected),
            cache_root=tmp_path / "cache",
            cache_namespace="lock",
        )
    assert not isinstance(caught.value, trust.RunnerAcquisitionError)


def test_authenticated_artifact_rejects_zero_progress_cache_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = b"authenticated"
    digest = hashlib.sha256(data).hexdigest()
    url = "https://files.pythonhosted.org/artifact.whl"
    monkeypatch.setattr(
        trust.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _Response(data, url),
    )
    monkeypatch.setattr(trust.os, "write", lambda _descriptor, _view: 0)

    with pytest.raises(trust.RunnerTrustError, match="cache write failed"):
        trust.authenticated_artifact_bytes(
            url=url,
            expected_sha256=digest,
            expected_size=len(data),
            cache_root=tmp_path / "cache",
            cache_namespace="lock",
        )

    namespace = tmp_path / "cache" / "lock"
    assert not tuple(namespace.glob(".*.tmp"))


def test_authenticated_artifact_wraps_atomic_cache_replace_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = b"authenticated"
    digest = hashlib.sha256(data).hexdigest()
    url = "https://files.pythonhosted.org/artifact.whl"
    monkeypatch.setattr(
        trust.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _Response(data, url),
    )

    def fail_replace(_source: Path, _destination: Path) -> None:
        raise OSError("replace denied")

    monkeypatch.setattr(trust.os, "replace", fail_replace)

    with pytest.raises(trust.RunnerTrustError, match="cache write failed"):
        trust.authenticated_artifact_bytes(
            url=url,
            expected_sha256=digest,
            expected_size=len(data),
            cache_root=tmp_path / "cache",
            cache_namespace="lock",
        )


def test_authenticated_artifact_rejects_unstable_persisted_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = b"authenticated"
    digest = hashlib.sha256(data).hexdigest()
    url = "https://files.pythonhosted.org/artifact.whl"
    monkeypatch.setattr(
        trust.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _Response(data, url),
    )
    monkeypatch.setattr(trust, "stable_regular_bytes", lambda *_args, **_kwargs: None)

    with pytest.raises(trust.RunnerTrustError, match="did not preserve exact bytes"):
        trust.authenticated_artifact_bytes(
            url=url,
            expected_sha256=digest,
            expected_size=len(data),
            cache_root=tmp_path / "cache",
            cache_namespace="lock",
        )


def test_runner_tree_digest_detects_drift_and_external_symlinks(tmp_path: Path) -> None:
    root = tmp_path / "runner"
    root.mkdir()
    bound = root / "bound.py"
    bound.write_text("value = 1\n")
    before = trust.tree_digest(root)
    assert before is not None

    bound.write_text("value = 2\n")
    assert trust.tree_digest(root) != before

    outside = tmp_path / "outside"
    outside.write_text("outside\n")
    (root / "escape").symlink_to(outside)
    assert trust.tree_digest(root) is None


def test_runner_tree_digest_excludes_only_declared_mutable_outputs(tmp_path: Path) -> None:
    root = tmp_path / "runner"
    scratch = root / "runner-scratch"
    scratch.mkdir(parents=True)
    immutable = root / "snapshot.py"
    report = root / "report.xml"
    immutable.write_text("value = 1\n")
    scratch.joinpath("temporary").write_text("first\n")
    report.write_text("first\n")
    exclusions = ("report.xml", "runner-scratch")
    before = trust.tree_digest(root, excluded_relative_paths=exclusions)
    assert before is not None

    scratch.joinpath("temporary").write_text("second\n")
    report.write_text("second\n")
    assert trust.tree_digest(root, excluded_relative_paths=exclusions) == before

    immutable.write_text("value = 2\n")
    assert trust.tree_digest(root, excluded_relative_paths=exclusions) != before
    assert (
        trust.tree_digest(
            root,
            excluded_relative_paths=("runner-scratch", "report.xml"),
        )
        is None
    )


def test_runner_tree_digest_prunes_a_large_excluded_scratch_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "runner"
    scratch = root / "runner-scratch"
    nested = scratch / "nested"
    nested.mkdir(parents=True)
    root.joinpath("bound.py").write_text("value = 1\n", encoding="utf-8")
    for index in range(64):
        nested.joinpath(f"transient-{index:03d}").write_text("temporary\n", encoding="utf-8")

    scratch_metadata = scratch.stat()
    scratch_identity = (scratch_metadata.st_dev, scratch_metadata.st_ino)
    original_scandir = trust.os.scandir

    def guarded_scandir(path: int | os.PathLike[str] | str) -> Any:
        if isinstance(path, int):
            metadata = os.fstat(path)
            if (metadata.st_dev, metadata.st_ino) == scratch_identity:
                raise AssertionError("excluded scratch directory was traversed")
        elif Path(path) == scratch:
            raise AssertionError("excluded scratch directory was traversed")
        return original_scandir(path)

    monkeypatch.setattr(trust, "MAX_RUNNER_TREE_ENTRIES", 4)
    monkeypatch.setattr(trust.os, "scandir", guarded_scandir)

    assert trust.tree_digest(root, excluded_relative_paths=("runner-scratch",)) is not None


def test_runner_tree_digest_stops_discovery_at_the_included_entry_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "runner"
    root.mkdir()
    for index in range(64):
        root.joinpath(f"included-{index:03d}").write_text("bound\n", encoding="utf-8")

    root_metadata = root.stat()
    root_identity = (root_metadata.st_dev, root_metadata.st_ino)
    original_scandir = trust.os.scandir
    root_entries_seen = 0

    class GuardedScandir:
        def __init__(self, iterator: Any, *, guard: bool) -> None:
            self._iterator = iterator
            self._guard = guard

        def __enter__(self) -> GuardedScandir:
            self._iterator.__enter__()
            return self

        def __exit__(self, *args: object) -> object:
            return self._iterator.__exit__(*args)

        def __iter__(self) -> GuardedScandir:
            return self

        def __next__(self) -> Any:
            nonlocal root_entries_seen
            entry = next(self._iterator)
            if self._guard:
                root_entries_seen += 1
                if root_entries_seen > 4:
                    raise AssertionError("included discovery continued beyond its entry bound")
            return entry

    def guarded_scandir(path: int | os.PathLike[str] | str) -> GuardedScandir:
        guard = False
        if isinstance(path, int):
            metadata = os.fstat(path)
            guard = (metadata.st_dev, metadata.st_ino) == root_identity
        elif Path(path) == root:
            guard = True
        return GuardedScandir(original_scandir(path), guard=guard)

    monkeypatch.setattr(trust, "MAX_RUNNER_TREE_ENTRIES", 4)
    monkeypatch.setattr(trust.os, "scandir", guarded_scandir)

    assert trust.tree_digest(root) is None
    assert root_entries_seen == 4


def test_runner_tree_digest_rejects_directory_replacement_before_descriptor_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "runner"
    included = root / "included"
    included.mkdir(parents=True)
    included.joinpath("bound.py").write_text("trusted\n", encoding="utf-8")
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    replacement.joinpath("bound.py").write_text("replacement\n", encoding="utf-8")
    displaced = tmp_path / "displaced"
    original_open = trust.os.open
    replaced = False

    def racing_open(
        path: int | os.PathLike[str] | str,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal replaced
        if path == "included" and dir_fd is not None and not replaced:
            replaced = True
            included.rename(displaced)
            replacement.rename(included)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(trust.os, "open", racing_open)

    assert trust.tree_digest(root) is None
    assert replaced


def test_stable_regular_bytes_rejects_descriptor_path_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "artifact"
    replacement = tmp_path / "replacement"
    displaced = tmp_path / "displaced"
    path.write_bytes(b"same bytes")
    replacement.write_bytes(b"same bytes")
    original_open = trust.os.open
    raced = False

    def racing_open(candidate: os.PathLike[str] | str, *args: Any, **kwargs: Any) -> int:
        nonlocal raced
        descriptor = original_open(candidate, *args, **kwargs)
        if Path(candidate) == path and not raced:
            raced = True
            path.rename(displaced)
            replacement.rename(path)
        return descriptor

    monkeypatch.setattr(trust.os, "open", racing_open)

    assert trust.stable_regular_bytes(path, maximum_bytes=1024) is None
    assert raced


def test_bind_executable_detects_restored_parent_directory_substitution(tmp_path: Path) -> None:
    root = tmp_path / "runner"
    trusted_bin = root / "bin"
    hostile_bin = root / "runner-scratch" / "hostile-bin"
    trusted_bin.mkdir(mode=0o700, parents=True)
    hostile_bin.mkdir(mode=0o700, parents=True)
    trusted = trusted_bin / "python"
    hostile = hostile_bin / "python"
    trusted.write_bytes(b"trusted-python")
    hostile.write_bytes(b"hostile-python")
    trusted.chmod(0o500)
    hostile.chmod(0o500)

    before = trust.bind_executable(trusted, required_root=root)
    assert before is not None

    displaced = root / "trusted-bin"
    trusted_bin.rename(displaced)
    hostile_bin.rename(trusted_bin)
    trusted_bin.rename(root / "runner-scratch" / "hostile-bin")
    displaced.rename(trusted_bin)

    after = trust.bind_executable(trusted, required_root=root)
    assert after is not None
    assert after != before


def test_runner_tree_digest_detects_restored_directory_substitution(tmp_path: Path) -> None:
    root = tmp_path / "runner"
    trusted_bin = root / "python" / "bin"
    hostile_bin = root / "runner-scratch" / "hostile-bin"
    trusted_bin.mkdir(mode=0o700, parents=True)
    hostile_bin.mkdir(mode=0o700, parents=True)
    trusted_bin.joinpath("python").write_bytes(b"trusted-python")
    hostile_bin.joinpath("python").write_bytes(b"hostile-python")
    exclusions = ("runner-scratch",)
    before = trust.tree_digest(root, excluded_relative_paths=exclusions)
    assert before is not None

    displaced = root / "python" / "trusted-bin"
    trusted_bin.rename(displaced)
    hostile_bin.rename(trusted_bin)
    trusted_bin.rename(root / "runner-scratch" / "hostile-bin")
    displaced.rename(trusted_bin)

    after = trust.tree_digest(root, excluded_relative_paths=exclusions)
    assert after is not None
    assert after != before


def test_bind_executable_rejects_group_writable_binary_and_parent(tmp_path: Path) -> None:
    root = tmp_path / "runner"
    binary_directory = root / "bin"
    binary_directory.mkdir(mode=0o700, parents=True)
    executable = binary_directory / "python"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o775)

    assert trust.bind_executable(executable, required_root=root) is None

    executable.chmod(0o755)
    binding = trust.bind_executable(executable, required_root=root)
    assert binding is not None
    assert binding.owner_uid == os.getuid()
    assert binding.owner_gid == os.getgid()

    binary_directory.chmod(0o777)
    assert trust.bind_executable(executable, required_root=root) is None


def test_runner_tree_digest_rejects_unsafe_root_and_nested_modes(tmp_path: Path) -> None:
    root = tmp_path / "runner"
    nested = root / "snapshot"
    nested.mkdir(mode=0o700, parents=True)
    nested.joinpath("source.py").write_text("value = 1\n", encoding="utf-8")
    root.chmod(0o700)
    initial = trust.tree_digest(root)
    assert initial is not None

    root.chmod(0o777)
    assert trust.tree_digest(root) is None
    root.chmod(0o700)

    nested.chmod(0o777)
    assert trust.tree_digest(root) is None
    nested.chmod(0o750)
    assert trust.tree_digest(root) not in {None, initial}


def _directory_runner(tmp_path: Path) -> trust.AuthenticatedRunner:
    root = tmp_path / "runner"
    snapshot = root / "snapshot"
    interpreter = root / "python-install" / "python"
    site_packages = root / "authenticated-site-packages"
    scratch = root / "runner-scratch"
    uv_root = root / "authenticated-uv"
    uv_path = uv_root / "uv"
    python_path = interpreter / "bin" / "python3.12"
    for directory in (snapshot, interpreter, site_packages, scratch, uv_root, python_path.parent):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
    root.chmod(0o700)
    python_path.write_bytes(b"python")
    python_path.chmod(0o700)
    uv_path.write_bytes(b"uv")
    uv_path.chmod(0o700)
    executable = trust.ExecutableBinding(
        lexical_path=python_path,
        resolved_path=python_path,
        sha256="a" * 64,
        size=6,
        mode=0o700,
        owner_uid=os.getuid(),
        owner_gid=os.getgid(),
    )
    uv_executable = trust.bind_executable(uv_path, required_root=uv_root)
    assert uv_executable is not None
    return trust.AuthenticatedRunner(
        root=root,
        snapshot_root=snapshot,
        python_path=python_path,
        site_packages=site_packages,
        interpreter_root=interpreter,
        scratch_root=scratch,
        uv=trust.PinnedUvBinding(executable=uv_executable, version="uv test", target="test"),
        python=executable,
        python_artifact_sha256="b" * 64,
        host_tool=trust.HostToolBinding(
            trust_root="test",
            system="test",
            machine="test",
            release="test",
            version="test",
            tool=None,
        ),
        python_version="3.12.13",
        lock_sha256="c" * 64,
        artifact_set_sha256="d" * 64,
        environment_sha256="e" * 64,
        excluded_tree_paths=("runner-scratch",),
        distribution_versions=(("pytest", "test"),),
    )


@pytest.mark.parametrize(
    "attribute",
    ["root", "snapshot_root", "interpreter_root", "site_packages", "scratch_root"],
)
def test_runner_directory_trust_rejects_each_writable_boundary(
    tmp_path: Path,
    attribute: str,
) -> None:
    runner = _directory_runner(tmp_path)
    assert trust._runner_directories_are_trusted(runner)

    path = getattr(runner, attribute)
    assert isinstance(path, Path)
    path.chmod(0o777)
    assert not trust._runner_directories_are_trusted(runner)


def test_runner_directory_trust_rejects_excluded_scratch_symlink(tmp_path: Path) -> None:
    runner = _directory_runner(tmp_path)
    replacement = runner.root / "private-scratch-replacement"
    replacement.mkdir(mode=0o700)
    runner.scratch_root.rmdir()
    runner.scratch_root.symlink_to(replacement, target_is_directory=True)

    assert runner.scratch_root.resolve(strict=True) == replacement
    assert not trust._runner_directories_are_trusted(runner)


def test_runner_directory_trust_requires_exact_private_uv_location(tmp_path: Path) -> None:
    runner = _directory_runner(tmp_path)
    uv_root = runner.uv.executable.lexical_path.parent
    uv_root.chmod(0o777)
    assert not trust._runner_directories_are_trusted(runner)
    uv_root.chmod(0o700)

    alternate_root = runner.root / "alternate-uv"
    alternate_root.mkdir(mode=0o700)
    alternate = alternate_root / "uv"
    alternate.write_bytes(b"uv")
    alternate.chmod(0o500)
    alternate_binding = trust.bind_executable(alternate, required_root=alternate_root)
    assert alternate_binding is not None
    forged = replace(
        runner,
        uv=replace(runner.uv, executable=alternate_binding),
    )
    assert not trust._runner_directories_are_trusted(forged)


def test_same_uv_binding_compares_the_complete_executable_binding(tmp_path: Path) -> None:
    path = tmp_path / "uv"
    metadata = trust.StableMetadataBinding(
        device=1,
        inode=2,
        mode=0o100755,
        nlink=1,
        size=1,
        mtime_ns=3,
        ctime_ns=4,
        owner_uid=os.getuid(),
        owner_gid=os.getgid(),
    )
    directory = trust.DirectoryBinding(path=tmp_path, metadata=metadata)
    executable = trust.ExecutableBinding(
        lexical_path=path,
        resolved_path=path,
        sha256="a" * 64,
        size=1,
        mode=0o755,
        owner_uid=os.getuid(),
        owner_gid=os.getgid(),
        lexical_metadata=metadata,
        resolved_metadata=metadata,
        directory_chain=(directory,),
    )
    expected = trust.PinnedUvBinding(executable=executable, version="uv test", target="target")
    assert trust._same_uv_binding(expected, expected)

    mutations = (
        replace(executable, lexical_path=tmp_path / "other-uv"),
        replace(executable, resolved_path=tmp_path / "other-uv"),
        replace(executable, mode=0o700),
        replace(executable, owner_uid=executable.owner_uid + 1),
        replace(executable, owner_gid=executable.owner_gid + 1),
        replace(
            executable,
            lexical_metadata=replace(metadata, ctime_ns=metadata.ctime_ns + 1),
        ),
        replace(
            executable,
            resolved_metadata=replace(metadata, inode=metadata.inode + 1),
        ),
        replace(executable, lexical_link_target="substituted-target"),
        replace(
            executable,
            directory_chain=(
                replace(
                    directory,
                    metadata=replace(metadata, mtime_ns=metadata.mtime_ns + 1),
                ),
            ),
        ),
    )
    for candidate in mutations:
        assert not trust._same_uv_binding(
            trust.PinnedUvBinding(executable=candidate, version="uv test", target="target"),
            expected,
        )


def test_python_artifact_pins_are_complete_for_supported_platforms() -> None:
    assert trust.PINNED_PYTHON_BUILD == "20260623"
    assert set(trust.PINNED_PYTHON_ARTIFACTS) == {
        ("darwin", "arm64"),
        ("darwin", "x86_64"),
        ("linux", "aarch64"),
        ("linux", "x86_64"),
    }
    for target, filename, url, digest, size in trust.PINNED_PYTHON_ARTIFACTS.values():
        assert target.startswith("cpython-3.12.13-")
        assert "+20260623-" in filename
        assert url.startswith(
            "https://github.com/astral-sh/python-build-standalone/releases/download/20260623/"
        )
        assert len(digest) == 64
        assert size > 20_000_000

    supported = set(trust.PINNED_PYTHON_ARTIFACTS)
    assert set(trust.PINNED_UV_SHA256) == supported
    assert set(trust.PINNED_UV_SIZE) == supported
    assert set(trust.PINNED_UV_TARGET) == supported
    assert set(trust.PINNED_UV_COMMIT_INFO) == supported


def test_offline_pinned_python_install_timeout_is_acquisition_not_trust(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bindings = _directory_runner(tmp_path / "bindings")
    root = tmp_path / "install"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(
        trust,
        "authenticated_artifact_bytes",
        lambda **_kwargs: b"authenticated-python-archive",
    )
    monkeypatch.setattr(trust, "host_tool_binding", lambda: bindings.host_tool)
    monkeypatch.setattr(
        trust,
        "resolve_pinned_uv",
        lambda *_args, **_kwargs: bindings.uv,
    )

    def timeout(*_args: Any, **_kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd="uv python install", timeout=120)

    monkeypatch.setattr(trust.subprocess, "run", timeout)
    with pytest.raises(
        trust.RunnerAcquisitionError,
        match="offline pinned Python installation timed out",
    ) as caught:
        trust._install_pinned_python(
            root,
            uv=bindings.uv,
            artifact_cache_root=tmp_path / "artifact-cache",
        )
    assert not isinstance(caught.value, trust.RunnerTrustError)


def test_authenticated_runner_import_probe_timeout_is_acquisition_not_trust(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bindings = _directory_runner(tmp_path / "bindings")
    root = tmp_path / "subject"
    snapshot = root / "snapshot"
    snapshot.mkdir(mode=0o700, parents=True)
    root.chmod(0o700)
    snapshot.chmod(0o700)
    snapshot.joinpath("uv.lock").write_text("version = 1\n", encoding="utf-8")
    interpreter_root = root / "python-install" / "target"
    python_path = interpreter_root / "bin" / "python3.12"
    python_path.parent.mkdir(mode=0o700, parents=True)
    python_path.write_bytes(b"python")
    scratch_root = root / "runner-scratch"
    scratch_root.mkdir(mode=0o700)
    python_binding = _executable_binding(python_path)

    monkeypatch.setattr(trust, "stage_pinned_uv", lambda _root: bindings.uv)
    monkeypatch.setattr(
        trust,
        "resolve_locked_wheels",
        lambda *_args, **_kwargs: (),
    )
    monkeypatch.setattr(
        trust,
        "_install_pinned_python",
        lambda *_args, **_kwargs: (
            interpreter_root,
            python_path,
            scratch_root,
            "a" * 64,
            bindings.host_tool,
        ),
    )

    def extract(_artifacts: object, site_packages: Path) -> None:
        site_packages.mkdir(mode=0o700)

    monkeypatch.setattr(trust, "extract_authenticated_wheels", extract)
    monkeypatch.setattr(
        trust,
        "bind_executable",
        lambda path, **_kwargs: python_binding if path == python_path else None,
    )

    def timeout(*_args: Any, **_kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd="authenticated import probe", timeout=30)

    monkeypatch.setattr(trust.subprocess, "run", timeout)
    with pytest.raises(
        trust.RunnerAcquisitionError,
        match="authenticated runner import probe timed out",
    ) as caught:
        trust.prepare_authenticated_runner(
            root,
            snapshot,
            root_distributions=frozenset({"pytest"}),
            artifact_cache_root=tmp_path / "artifact-cache",
        )
    assert not isinstance(caught.value, trust.RunnerTrustError)


def test_runner_distribution_version_is_canonical_and_unique(tmp_path: Path) -> None:
    runner = _directory_runner(tmp_path)
    assert runner.distribution_version("PyTest") == "test"

    with pytest.raises(trust.RunnerTrustError, match="not unique"):
        replace(runner, distribution_versions=()).distribution_version("pytest")
    with pytest.raises(trust.RunnerTrustError, match="not unique"):
        replace(
            runner,
            distribution_versions=(("pytest", "first"), ("pytest", "second")),
        ).distribution_version("pytest")


def test_bind_executable_accepts_in_root_symlink_and_rejects_escape(tmp_path: Path) -> None:
    root = tmp_path / "runner"
    binary_directory = root / "bin"
    binary_directory.mkdir(mode=0o700, parents=True)
    binary_directory.chmod(0o700)
    root.chmod(0o700)
    target = binary_directory / "python-real"
    target.write_bytes(b"python")
    target.chmod(0o500)
    link = binary_directory / "python"
    link.symlink_to(target.name)

    binding = trust.bind_executable(link, required_root=root)
    assert binding is not None
    assert binding.lexical_link_target == target.name
    assert binding.resolved_path == target

    outside = tmp_path / "outside-python"
    outside.write_bytes(b"outside")
    outside.chmod(0o500)
    link.unlink()
    link.symlink_to(outside)
    assert trust.bind_executable(link, required_root=root) is None


def test_bind_executable_rejects_missing_unsafe_root_and_outside_path(tmp_path: Path) -> None:
    root = tmp_path / "runner"
    root.mkdir(mode=0o700)
    executable = tmp_path / "python"
    executable.write_bytes(b"python")
    executable.chmod(0o500)

    assert trust.bind_executable(tmp_path / "missing", required_root=root) is None
    assert trust.bind_executable(executable, required_root=root) is None

    root.chmod(0o777)
    assert trust.bind_executable(executable, required_root=root) is None


def test_resolve_pinned_uv_fails_closed_across_platform_process_and_rebind(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = tmp_path / "uv"
    binding = _executable_binding(candidate)
    monkeypatch.setattr(trust.platform, "system", lambda: "Unsupported")
    monkeypatch.setattr(trust.platform, "machine", lambda: "machine")
    with pytest.raises(trust.RunnerTrustError, match="unsupported"):
        trust.resolve_pinned_uv(candidate)

    monkeypatch.setattr(trust.platform, "system", lambda: "TestOS")
    monkeypatch.setattr(trust.platform, "machine", lambda: "TestMachine")
    monkeypatch.setitem(trust.PINNED_UV_SHA256, ("testos", "testmachine"), "a" * 64)
    monkeypatch.setitem(trust.PINNED_UV_TARGET, ("testos", "testmachine"), "test-target")
    commit_info = {
        "short_commit_hash": "abc123",
        "commit_hash": "abc123def456",
        "commit_date": "2026-07-07",
        "last_tag": None,
        "commits_since_last_tag": 0,
    }
    monkeypatch.setitem(
        trust.PINNED_UV_COMMIT_INFO,
        ("testos", "testmachine"),
        commit_info,
    )
    monkeypatch.setattr(trust, "bind_executable", lambda _path, **_kwargs: binding)

    def fail_run(*_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired("uv", 10)

    monkeypatch.setattr(trust.subprocess, "run", fail_run)
    with pytest.raises(
        trust.RunnerAcquisitionError,
        match="version identity verification timed out",
    ) as caught:
        trust.resolve_pinned_uv(candidate)
    assert not isinstance(caught.value, trust.RunnerTrustError)

    completed = subprocess.CompletedProcess(
        args=(str(candidate), "self", "version", "--output-format", "json"),
        returncode=0,
        stdout=json.dumps(
            {
                "package_name": "uv",
                "version": "0.11.28",
                "commit_info": commit_info,
                "target_triple": "test-target",
            }
        ),
        stderr="",
    )
    monkeypatch.setattr(trust.subprocess, "run", lambda *_args, **_kwargs: completed)
    bindings = iter((binding, replace(binding, size=2)))
    monkeypatch.setattr(trust, "bind_executable", lambda _path, **_kwargs: next(bindings))
    with pytest.raises(trust.RunnerTrustError, match="changed during"):
        trust.resolve_pinned_uv(candidate)


def test_stage_pinned_uv_authenticates_unsafe_source_but_executes_only_private_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_bytes = b"pinned official uv bytes"
    source_root = tmp_path / "hostedtoolcache"
    source_root.mkdir(mode=0o700)
    source = source_root / "uv"
    source.write_bytes(source_bytes)
    source.chmod(0o500)
    source_root.chmod(0o777)
    runner_root = tmp_path / "runner"
    runner_root.mkdir(mode=0o700)
    runner_root.chmod(0o700)
    key = ("testos", "testmachine")
    monkeypatch.setattr(trust.platform, "system", lambda: "TestOS")
    monkeypatch.setattr(trust.platform, "machine", lambda: "TestMachine")
    monkeypatch.setitem(trust.PINNED_UV_SHA256, key, hashlib.sha256(source_bytes).hexdigest())
    monkeypatch.setitem(trust.PINNED_UV_SIZE, key, len(source_bytes))
    monkeypatch.setitem(trust.PINNED_UV_TARGET, key, "test-target")
    monkeypatch.setitem(trust.PINNED_UV_COMMIT_INFO, key, None)
    observed_paths: list[Path] = []

    def exact_identity(
        arguments: tuple[str, ...],
        **_kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        observed_paths.append(Path(arguments[0]))
        return subprocess.CompletedProcess(
            args=arguments,
            returncode=0,
            stdout=json.dumps(
                {
                    "package_name": "uv",
                    "version": "0.11.28",
                    "commit_info": None,
                    "target_triple": "test-target",
                }
            ),
            stderr="",
        )

    monkeypatch.setattr(trust.subprocess, "run", exact_identity)

    assert trust.bind_executable(source) is None
    staged = trust.stage_pinned_uv(runner_root, source)
    expected_path = runner_root / "authenticated-uv" / "uv"
    assert observed_paths == [expected_path]
    assert staged.executable.resolved_path == expected_path
    assert staged.executable.sha256 == hashlib.sha256(source_bytes).hexdigest()
    assert stat.S_IMODE(expected_path.stat().st_mode) == 0o500

    source.unlink()
    rebound = trust.resolve_pinned_uv(expected_path, required_root=expected_path.parent)
    assert trust._same_uv_binding(rebound, staged)
    assert observed_paths == [expected_path, expected_path]


def test_stage_pinned_uv_rejects_unstable_or_inexact_acquisition_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner_root = tmp_path / "runner"
    runner_root.mkdir(mode=0o700)
    runner_root.chmod(0o700)
    source_bytes = b"official"
    source = tmp_path / "uv"
    source.write_bytes(source_bytes)
    source.chmod(0o500)
    key = ("testos", "testmachine")
    monkeypatch.setattr(trust.platform, "system", lambda: "TestOS")
    monkeypatch.setattr(trust.platform, "machine", lambda: "TestMachine")
    monkeypatch.setitem(trust.PINNED_UV_SIZE, key, len(source_bytes))
    monkeypatch.setitem(trust.PINNED_UV_SHA256, key, "0" * 64)

    with pytest.raises(trust.RunnerTrustError, match="pinned official release"):
        trust.stage_pinned_uv(runner_root, source)
    assert not (runner_root / "authenticated-uv").exists()

    monkeypatch.setitem(trust.PINNED_UV_SHA256, key, hashlib.sha256(source_bytes).hexdigest())
    link = tmp_path / "uv-link"
    link.symlink_to(source)
    with pytest.raises(trust.RunnerTrustError, match="stable official-size file"):
        trust.stage_pinned_uv(runner_root, link)

    hardlink = tmp_path / "uv-hardlink"
    os.link(source, hardlink)
    with pytest.raises(trust.RunnerTrustError, match="stable official-size file"):
        trust.stage_pinned_uv(runner_root, source)
    hardlink.unlink()

    fifo = tmp_path / "uv-fifo"
    os.mkfifo(fifo)
    with pytest.raises(trust.RunnerTrustError, match="stable official-size file"):
        trust.stage_pinned_uv(runner_root, fifo)


def test_stage_pinned_uv_rejects_preexisting_private_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_bytes = b"official"
    source = tmp_path / "uv"
    source.write_bytes(source_bytes)
    source.chmod(0o500)
    runner_root = tmp_path / "runner"
    runner_root.mkdir(mode=0o700)
    runner_root.chmod(0o700)
    staged_root = runner_root / "authenticated-uv"
    staged_root.mkdir(mode=0o700)
    key = ("testos", "testmachine")
    monkeypatch.setattr(trust.platform, "system", lambda: "TestOS")
    monkeypatch.setattr(trust.platform, "machine", lambda: "TestMachine")
    monkeypatch.setitem(trust.PINNED_UV_SIZE, key, len(source_bytes))
    monkeypatch.setitem(trust.PINNED_UV_SHA256, key, hashlib.sha256(source_bytes).hexdigest())

    with pytest.raises(trust.RunnerTrustError, match="unsafe or already exists"):
        trust.stage_pinned_uv(runner_root, source)


def test_resolve_pinned_uv_requires_exact_structured_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = tmp_path / "uv"
    binding = _executable_binding(candidate)
    key = ("testos", "testmachine")
    monkeypatch.setattr(trust.platform, "system", lambda: "TestOS")
    monkeypatch.setattr(trust.platform, "machine", lambda: "TestMachine")
    monkeypatch.setitem(trust.PINNED_UV_SHA256, key, "a" * 64)
    monkeypatch.setitem(trust.PINNED_UV_TARGET, key, "test-target")
    monkeypatch.setitem(trust.PINNED_UV_COMMIT_INFO, key, None)
    monkeypatch.setattr(trust, "bind_executable", lambda _path, **_kwargs: binding)

    malformed_outputs = (
        '{"package_name":"uv","package_name":"uv","version":"0.11.28",'
        '"commit_info":null,"target_triple":"test-target"}',
        json.dumps(
            {
                "package_name": "uv",
                "version": "0.11.28",
                "commit_info": {"unexpected": "commit"},
                "target_triple": "test-target",
            }
        ),
        json.dumps(
            {
                "package_name": "uv",
                "version": "0.11.28",
                "commit_info": None,
                "target_triple": "cross-target",
            }
        ),
    )
    for stdout in malformed_outputs:
        completed = subprocess.CompletedProcess(
            args=(str(candidate),),
            returncode=0,
            stdout=stdout,
            stderr="",
        )

        def malformed_identity(
            *_args: Any,
            _completed: subprocess.CompletedProcess[str] = completed,
            **_kwargs: Any,
        ) -> subprocess.CompletedProcess[str]:
            return _completed

        monkeypatch.setattr(trust.subprocess, "run", malformed_identity)
        with pytest.raises(trust.RunnerTrustError, match="invalid version identity"):
            trust.resolve_pinned_uv(candidate)


def test_host_tool_binding_covers_supported_and_rejected_hosts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(trust.platform, "machine", lambda: "machine")
    monkeypatch.setattr(trust.platform, "release", lambda: "release")
    monkeypatch.setattr(trust.platform, "version", lambda: "version")

    monkeypatch.setattr(trust.platform, "system", lambda: "Linux")
    linux = trust.host_tool_binding()
    assert linux.trust_root == "host-os-linux-dynamic-loader"
    assert linux.tool is None

    monkeypatch.setattr(trust.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(trust, "_bind_host_tool", lambda _path: None)
    with pytest.raises(trust.RunnerTrustError, match="install_name_tool"):
        trust.host_tool_binding()

    monkeypatch.setattr(trust.platform, "system", lambda: "UnknownOS")
    with pytest.raises(trust.RunnerTrustError, match="unsupported"):
        trust.host_tool_binding()


def test_ensure_private_directory_returns_false_on_creation_error(tmp_path: Path) -> None:
    parent_file = tmp_path / "not-a-directory"
    parent_file.write_bytes(b"file")
    assert not trust.ensure_private_directory(parent_file / "child")


@pytest.mark.parametrize(
    ("member", "expected"),
    [
        ("pkg\\module.py", None),
        ("pkg\x00module.py", None),
        ("/pkg/module.py", None),
        ("pkg/../module.py", None),
        ("pkg.data/scripts/tool", None),
        ("pkg.data/purelib/pkg/module.py", ("pkg", "module.py")),
        ("pkg.data/platlib/pkg.so", ("pkg.so",)),
    ],
)
def test_wheel_output_parts_enforces_installable_paths(
    member: str,
    expected: tuple[str, ...] | None,
) -> None:
    assert trust._wheel_output_parts(member) == expected


def test_extract_authenticated_wheels_maps_data_and_writes_read_only_files(tmp_path: Path) -> None:
    directory = zipfile.ZipInfo("pkg/")
    directory.external_attr = (stat.S_IFDIR | 0o755) << 16
    module = zipfile.ZipInfo("demo.data/purelib/pkg/module.py")
    module.external_attr = (stat.S_IFREG | 0o644) << 16
    archive = _wheel_archive((directory, b""), (module, b"value = 1\n"))
    wheel = trust.LockedWheel("demo", "1", "https://example", "a" * 64, len(archive), "demo.whl")
    destination = tmp_path / "site-packages"

    trust.extract_authenticated_wheels(((wheel, archive),), destination)

    installed = destination / "pkg" / "module.py"
    assert installed.read_bytes() == b"value = 1\n"
    assert stat.S_IMODE(installed.stat().st_mode) == 0o400


def test_extract_authenticated_wheels_rejects_empty_existing_and_bad_archives(
    tmp_path: Path,
) -> None:
    empty_destination = tmp_path / "empty"
    with pytest.raises(trust.RunnerTrustError, match="extracted no files"):
        trust.extract_authenticated_wheels((), empty_destination)

    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(trust.RunnerTrustError, match="already exists"):
        trust.extract_authenticated_wheels((), existing)

    wheel = trust.LockedWheel("demo", "1", "https://example", "a" * 64, 7, "demo.whl")
    with pytest.raises(trust.RunnerTrustError, match="extraction failed"):
        trust.extract_authenticated_wheels(((wheel, b"not-zip"),), tmp_path / "bad")


def test_extract_authenticated_wheels_rejects_metadata_and_collisions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheel = trust.LockedWheel("demo", "1", "https://example", "a" * 64, 1, "demo.whl")

    monkeypatch.setattr(trust, "MAX_WHEEL_ENTRIES", 0)
    one_file = _wheel_archive(("module.py", b"x"))
    with pytest.raises(trust.RunnerTrustError, match="entry count"):
        trust.extract_authenticated_wheels(((wheel, one_file),), tmp_path / "entries")
    monkeypatch.setattr(trust, "MAX_WHEEL_ENTRIES", 10_000)

    unsafe = _wheel_archive(("../escape.py", b"x"))
    with pytest.raises(trust.RunnerTrustError, match="path is unsafe"):
        trust.extract_authenticated_wheels(((wheel, unsafe),), tmp_path / "unsafe")

    special = zipfile.ZipInfo("link")
    special.external_attr = (stat.S_IFLNK | 0o777) << 16
    with pytest.raises(trust.RunnerTrustError, match="special file"):
        trust.extract_authenticated_wheels(
            ((wheel, _wheel_archive((special, b"target"))),),
            tmp_path / "special",
        )

    incoherent = zipfile.ZipInfo("directory/")
    incoherent.external_attr = (stat.S_IFREG | 0o644) << 16
    with pytest.raises(trust.RunnerTrustError, match="type is incoherent"):
        trust.extract_authenticated_wheels(
            ((wheel, _wheel_archive((incoherent, b""))),),
            tmp_path / "incoherent",
        )

    monkeypatch.setattr(trust, "MAX_WHEEL_EXPANDED_BYTES", 0)
    with pytest.raises(trust.RunnerTrustError, match="expansion exceeded"):
        trust.extract_authenticated_wheels(((wheel, one_file),), tmp_path / "expanded")

    monkeypatch.setattr(trust, "MAX_WHEEL_EXPANDED_BYTES", 128 * 1024 * 1024)
    parent_file = _wheel_archive(("pkg", b"file"), ("pkg/module.py", b"module"))
    with pytest.raises(trust.RunnerTrustError, match="path collides with a file"):
        trust.extract_authenticated_wheels(((wheel, parent_file),), tmp_path / "parent-file")

    directory = zipfile.ZipInfo("PKG/")
    directory.external_attr = (stat.S_IFDIR | 0o755) << 16
    directory_collision = _wheel_archive(("pkg", b"file"), (directory, b""))
    with pytest.raises(trust.RunnerTrustError, match="directory collides"):
        trust.extract_authenticated_wheels(
            ((wheel, directory_collision),),
            tmp_path / "directory-collision",
        )

    lower_directory = zipfile.ZipInfo("pkg/")
    lower_directory.external_attr = (stat.S_IFDIR | 0o755) << 16
    file_collision = _wheel_archive((lower_directory, b""), ("PKG", b"file"))
    with pytest.raises(trust.RunnerTrustError, match="file collides"):
        trust.extract_authenticated_wheels(
            ((wheel, file_collision),),
            tmp_path / "file-collision",
        )


def test_extract_authenticated_wheels_rejects_encryption_truncation_and_write_stall(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheel = trust.LockedWheel("demo", "1", "https://example", "a" * 64, 1, "demo.whl")
    stalled_archive = _wheel_archive(("module.py", b"module"))

    class FakeArchive:
        def __init__(self, info: SimpleNamespace, payload: bytes = b"") -> None:
            self.info = info
            self.payload = payload

        def __enter__(self) -> FakeArchive:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def infolist(self) -> list[SimpleNamespace]:
            return [self.info]

        def open(self, _info: SimpleNamespace, _mode: str) -> io.BytesIO:
            return io.BytesIO(self.payload)

    encrypted = SimpleNamespace(flag_bits=1)
    monkeypatch.setattr(trust.zipfile, "ZipFile", lambda _stream: FakeArchive(encrypted))
    with pytest.raises(trust.RunnerTrustError, match="encrypted"):
        trust.extract_authenticated_wheels(((wheel, b"fake"),), tmp_path / "encrypted")

    regular = SimpleNamespace(
        flag_bits=0,
        filename="module.py",
        external_attr=(stat.S_IFREG | 0o644) << 16,
        file_size=2,
        compress_size=2,
        compress_type=zipfile.ZIP_STORED,
        is_dir=lambda: False,
    )
    monkeypatch.setattr(trust.zipfile, "ZipFile", lambda _stream: FakeArchive(regular, b"x"))
    with pytest.raises(trust.RunnerTrustError, match="truncated"):
        trust.extract_authenticated_wheels(((wheel, b"fake"),), tmp_path / "truncated")

    monkeypatch.undo()
    monkeypatch.setattr(trust.os, "write", lambda _descriptor, _view: 0)
    with pytest.raises(trust.RunnerTrustError, match="extraction failed"):
        trust.extract_authenticated_wheels(((wheel, stalled_archive),), tmp_path / "stalled")


def test_write_exclusive_stable_bytes_rejects_existing_stalled_and_changed_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    existing = tmp_path / "existing"
    existing.write_bytes(b"existing")
    with pytest.raises(trust.RunnerTrustError, match="already exists"):
        trust._write_exclusive_stable_bytes(existing, b"new")

    monkeypatch.setattr(trust.os, "write", lambda _descriptor, _view: 0)
    with pytest.raises(trust.RunnerTrustError, match="mirror write failed"):
        trust._write_exclusive_stable_bytes(tmp_path / "stalled", b"new")

    monkeypatch.undo()
    monkeypatch.setattr(trust, "stable_regular_bytes", lambda *_args, **_kwargs: None)
    with pytest.raises(trust.RunnerTrustError, match="did not preserve"):
        trust._write_exclusive_stable_bytes(tmp_path / "changed", b"new")


def test_runner_path_checks_fail_closed_on_missing_and_external_paths(tmp_path: Path) -> None:
    runner = _directory_runner(tmp_path)
    runner.site_packages.rmdir()
    assert not trust._runner_directories_are_trusted(runner)

    external = tmp_path / "external"
    external.mkdir()
    escaped = replace(runner, site_packages=external)
    assert not trust._runner_directories_are_trusted(escaped)


def test_runner_is_unchanged_returns_false_when_rebinding_raises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _directory_runner(tmp_path)

    def fail_resolve(
        _path: Path | None = None,
        *,
        required_root: Path | None = None,
    ) -> trust.PinnedUvBinding:
        del required_root
        raise trust.RunnerTrustError("rebind failed")

    monkeypatch.setattr(trust, "resolve_pinned_uv", fail_resolve)
    assert not trust.runner_is_unchanged(runner)


def test_runner_rebinds_only_staged_uv_without_ambient_rediscovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _directory_runner(tmp_path)
    lock_bytes = b"lock"
    (runner.snapshot_root / "uv.lock").write_bytes(lock_bytes)
    runner = replace(runner, lock_sha256=hashlib.sha256(lock_bytes).hexdigest())
    key = (trust.platform.system().casefold(), trust.platform.machine().casefold())
    artifact = trust.PINNED_PYTHON_ARTIFACTS[key]
    monkeypatch.setitem(
        trust.PINNED_PYTHON_ARTIFACTS,
        key,
        (*artifact[:3], runner.python_artifact_sha256, artifact[4]),
    )
    observed: list[tuple[Path | None, Path | None]] = []

    def rebind_staged(
        path: Path | None = None,
        *,
        required_root: Path | None = None,
    ) -> trust.PinnedUvBinding:
        observed.append((path, required_root))
        return runner.uv

    monkeypatch.setattr(trust, "resolve_pinned_uv", rebind_staged)
    monkeypatch.setattr(
        trust,
        "bind_executable",
        lambda path, **_kwargs: runner.python if path == runner.python_path else None,
    )
    monkeypatch.setattr(trust, "host_tool_binding", lambda: runner.host_tool)
    monkeypatch.setattr(trust, "tree_digest", lambda *_args, **_kwargs: runner.environment_sha256)

    assert trust.runner_is_unchanged(runner)
    assert observed == [
        (runner.uv.executable.lexical_path, runner.uv.executable.lexical_path.parent)
    ]


def _lock_package(
    *,
    dependencies: object = (),
    wheels: object = (),
    source: object = None,
) -> dict[str, object]:
    return {
        "name": "demo",
        "version": "1.0",
        "source": source or {"registry": "https://pypi.org/simple"},
        "dependencies": list(dependencies) if isinstance(dependencies, tuple) else dependencies,
        "wheels": list(wheels) if isinstance(wheels, tuple) else wheels,
    }


def test_resolve_locked_packages_rejects_malformed_inventory_and_closure() -> None:
    with pytest.raises(trust.RunnerTrustError, match="no package inventory"):
        trust.resolve_locked_packages({}, frozenset({"demo"}))
    with pytest.raises(trust.RunnerTrustError, match="inventory is invalid"):
        trust.resolve_locked_packages({"package": ["demo"]}, frozenset({"demo"}))
    with pytest.raises(trust.RunnerTrustError, match="not unique"):
        trust.resolve_locked_packages(
            {"package": [_lock_package(), _lock_package()]},
            frozenset({"demo"}),
        )
    with pytest.raises(trust.RunnerTrustError, match="not registry-bound"):
        trust.resolve_locked_packages(
            {"package": [_lock_package(source={"path": "."})]},
            frozenset({"demo"}),
        )
    with pytest.raises(trust.RunnerTrustError, match="dependency is invalid"):
        trust.resolve_locked_packages(
            {"package": [_lock_package(dependencies=("invalid",))]},
            frozenset({"demo"}),
        )
    with pytest.raises(trust.RunnerTrustError, match="marker is invalid"):
        trust.resolve_locked_packages(
            {
                "package": [
                    _lock_package(dependencies=({"name": "child", "marker": 1},)),
                ]
            },
            frozenset({"demo"}),
        )
    with pytest.raises(trust.RunnerTrustError, match="marker cannot evaluate"):
        trust.resolve_locked_packages(
            {
                "package": [
                    _lock_package(
                        dependencies=({"name": "child", "marker": "python_version ??? '3'"},)
                    ),
                ]
            },
            frozenset({"demo"}),
        )


def test_target_tags_rejects_unsupported_platform_and_empty_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(trust.platform, "system", lambda: "Unsupported")
    monkeypatch.setattr(trust.platform, "machine", lambda: "machine")
    with pytest.raises(trust.RunnerTrustError, match="unsupported"):
        trust._target_tags(("any",))

    monkeypatch.setitem(trust.PINNED_UV_TARGET, ("unsupported", "machine"), "target")
    with pytest.raises(trust.RunnerTrustError, match="tags are unavailable"):
        trust._target_tags(())


def _wheel_binding(
    filename: str = "demo-1.0-py3-none-any.whl",
    *,
    url: str | None = None,
    digest: object = "sha256:" + "a" * 64,
    size: object = 1,
) -> dict[str, object]:
    return {
        "url": url or f"https://files.pythonhosted.org/packages/{filename}",
        "hash": digest,
        "size": size,
    }


def _resolve_demo_wheels(wheels: object) -> tuple[trust.LockedWheel, ...]:
    return trust.resolve_locked_wheels(
        {"package": [_lock_package(wheels=wheels)]},
        root_distributions=frozenset({"demo"}),
        target_platform_tags=("any",),
    )


def test_resolve_locked_wheels_rejects_invalid_entries_authorities_and_names() -> None:
    with pytest.raises(trust.RunnerTrustError, match="wheels are missing"):
        _resolve_demo_wheels(None)
    with pytest.raises(trust.RunnerTrustError, match="entry is invalid"):
        _resolve_demo_wheels(["wheel"])
    with pytest.raises(trust.RunnerTrustError, match="binding is invalid"):
        _resolve_demo_wheels([_wheel_binding(digest="sha256:bad")])
    with pytest.raises(trust.RunnerTrustError, match="URL is invalid"):
        _resolve_demo_wheels(
            [
                _wheel_binding(
                    url="https://[malformed/demo-1.0-py3-none-any.whl",
                )
            ]
        )
    with pytest.raises(trust.RunnerTrustError, match="authority is invalid"):
        _resolve_demo_wheels(
            [_wheel_binding(url="http://files.pythonhosted.org/demo-1.0-py3-none-any.whl")]
        )
    with pytest.raises(trust.RunnerTrustError, match="filename is invalid"):
        _resolve_demo_wheels([_wheel_binding("not-a-wheel.whl")])


def test_resolve_locked_wheels_rejects_absent_and_ambiguous_compatibility() -> None:
    with pytest.raises(trust.RunnerTrustError, match="no compatible"):
        _resolve_demo_wheels([_wheel_binding("demo-1.0-cp311-cp311-win_amd64.whl")])

    wheel = _wheel_binding()
    with pytest.raises(trust.RunnerTrustError, match="selection is ambiguous"):
        _resolve_demo_wheels([wheel, dict(wheel)])
