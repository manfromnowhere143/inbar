from __future__ import annotations

import base64
import hashlib
import os
import sys
from importlib import metadata
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

import fieldtrue.runtime as runtime
from fieldtrue.runtime import RuntimeProvenanceError


def _record_hash(data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return f"sha256={digest.decode('ascii')}"


def _write_distribution(
    tmp_path: Path,
    *,
    name: str = "example-dependency",
    version: str = "1.0",
) -> tuple[metadata.Distribution, Path, Path]:
    prefix = tmp_path / "runtime"
    site_root = prefix / "lib" / "python3.12" / "site-packages"
    package = site_root / name.replace("-", "_")
    dist_info = site_root / f"{name.replace('-', '_')}-{version}.dist-info"
    package.mkdir(parents=True)
    dist_info.mkdir()
    module = package / "__init__.py"
    module.write_bytes(b"VALUE = 1\n")
    metadata_file = dist_info / "METADATA"
    metadata_file.write_text(
        f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\n",
        encoding="utf-8",
    )
    record = dist_info / "RECORD"
    module_name = module.relative_to(site_root).as_posix()
    metadata_name = metadata_file.relative_to(site_root).as_posix()
    record_name = record.relative_to(site_root).as_posix()
    record.write_text(
        f"{module_name},{_record_hash(module.read_bytes())},{module.stat().st_size}\n"
        f"{metadata_name},{_record_hash(metadata_file.read_bytes())},{metadata_file.stat().st_size}\n"
        f"{record_name},,\n",
        encoding="utf-8",
    )
    return metadata.Distribution.at(dist_info), prefix, record


def _frozen_distribution(distribution: metadata.Distribution) -> SimpleNamespace:
    return SimpleNamespace(
        metadata=distribution.metadata,
        version=distribution.version,
        files=list(distribution.files or ()),
        locate_file=distribution.locate_file,
    )


def _lock(packages: str, dependencies: str = "[]") -> bytes:
    return (
        "version = 1\n"
        "[[package]]\n"
        'name = "fieldtrue"\n'
        'source = { editable = "." }\n'
        f"dependencies = {dependencies}\n"
        f"{packages}"
    ).encode()


def test_stable_read_rejects_unsafe_inputs_and_open_races(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "artifact"
    path.write_bytes(b"bound")

    with pytest.raises(RuntimeProvenanceError, match="no-follow"):
        runtime._stable_regular_bytes(path, maximum_bytes=-1)

    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(RuntimeProvenanceError, match="unsafe"):
        runtime._stable_regular_bytes(link, maximum_bytes=10)

    missing = tmp_path / "missing"
    with pytest.raises(RuntimeProvenanceError, match="cannot be read"):
        runtime._stable_regular_bytes(missing, maximum_bytes=10)

    real_fstat = runtime.os.fstat
    calls = 0

    def changed_fstat(descriptor: int) -> Any:
        nonlocal calls
        observed = real_fstat(descriptor)
        calls += 1
        if calls != 1:
            return observed
        values = {field: getattr(observed, field) for field in runtime._STABLE_STAT_FIELDS}
        values["st_mtime_ns"] += 1
        return SimpleNamespace(**values)

    monkeypatch.setattr(runtime.os, "fstat", changed_fstat)
    with pytest.raises(RuntimeProvenanceError, match="before it was opened"):
        runtime._stable_regular_bytes(path, maximum_bytes=10)


def test_runtime_roots_and_logical_paths_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing = tmp_path / "missing"
    with pytest.raises(RuntimeProvenanceError, match="root cannot be resolved"):
        runtime._resolved_roots(missing)

    regular = tmp_path / "regular"
    regular.write_text("not a root", encoding="utf-8")
    with pytest.raises(RuntimeProvenanceError, match="not a directory"):
        runtime._resolved_roots(regular)

    root = tmp_path / "root"
    child = root / "nested" / "file.py"
    child.parent.mkdir(parents=True)
    child.write_text("VALUE = 1\n", encoding="utf-8")
    roots = (("fixture", root.resolve()),)
    assert runtime._logical_path(root, roots) == "fixture"
    assert runtime._logical_path(child, roots) == "fixture/nested/file.py"
    assert runtime._logical_search_path(root, roots) == {"path": "fixture", "exists": True}
    assert runtime._logical_search_path(root / "absent", roots) == {
        "path": "fixture/absent",
        "exists": False,
    }
    with pytest.raises(RuntimeProvenanceError, match="cannot be resolved"):
        runtime._logical_path(root / "absent", roots)
    with pytest.raises(RuntimeProvenanceError, match="outside"):
        runtime._logical_path(regular, roots)
    with pytest.raises(RuntimeProvenanceError, match="escapes"):
        runtime._logical_search_path(regular, roots)

    original_resolve = Path.resolve

    def broken_resolve(self: Path, *args: object, **kwargs: object) -> Path:
        if self == root / "broken-search":
            raise OSError("synthetic normalization failure")
        return original_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", broken_resolve)
    with pytest.raises(RuntimeProvenanceError, match="cannot be normalized"):
        runtime._logical_search_path(root / "broken-search", roots)


def test_environment_snapshot_enforces_each_resource_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runtime.os, "environ", {"A": "B"})
    monkeypatch.setattr(runtime, "_MAX_ENVIRONMENT_ENTRIES", 0)
    with pytest.raises(RuntimeProvenanceError, match="entry bound"):
        runtime._snapshot_environment()

    monkeypatch.setattr(runtime, "_MAX_ENVIRONMENT_ENTRIES", 10)
    monkeypatch.setattr(runtime, "_MAX_ENVIRONMENT_NAME_BYTES", 0)
    with pytest.raises(RuntimeProvenanceError, match="field bound"):
        runtime._snapshot_environment()

    monkeypatch.setattr(runtime, "_MAX_ENVIRONMENT_NAME_BYTES", 10)
    monkeypatch.setattr(runtime, "_MAX_ENVIRONMENT_BYTES", 0)
    with pytest.raises(RuntimeProvenanceError, match="byte bound"):
        runtime._snapshot_environment()

    monkeypatch.setattr(runtime, "_MAX_ENVIRONMENT_BYTES", 10)
    monkeypatch.setattr(runtime.os, "environ", {"\udcff": "value"})
    with pytest.raises(RuntimeProvenanceError, match="strict UTF-8"):
        runtime._snapshot_environment()


def test_startup_provenance_rejects_loaded_hooks_and_wrong_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = Path.cwd()
    roots = runtime._resolved_roots(repo)
    monkeypatch.setitem(sys.modules, "usercustomize", ModuleType("usercustomize"))
    with pytest.raises(RuntimeProvenanceError, match="usercustomize"):
        runtime._startup_provenance(repo, roots)

    monkeypatch.delitem(sys.modules, "usercustomize")
    with pytest.raises(RuntimeProvenanceError, match="repository root"):
        runtime._startup_provenance(tmp_path, roots)


def test_executable_and_interpreter_manifests_bind_symlinks_and_libraries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "runtime"
    root.mkdir()
    executable = root / "python"
    executable.write_bytes(b"python executable")
    base_executable = root / "python-base"
    base_executable.write_bytes(b"base executable")
    library = root / "libpython.test"
    library.write_bytes(b"python library")
    framework = root / "Python.framework"
    framework.write_bytes(b"framework")
    link = root / "python-link"
    link.symlink_to(executable.name)
    roots = (("runtime", root.resolve()),)

    manifest = runtime._executable_manifest(link, roots)
    assert manifest["resolved_path"] == "runtime/python"
    assert manifest["link_target_sha256"] is not None

    monkeypatch.setattr(sys, "executable", str(link))
    monkeypatch.setattr(sys, "_base_executable", str(base_executable))

    def config_value(name: str) -> str | None:
        return {
            "LIBDIR": str(root),
            "LDLIBRARY": library.name,
            "PYTHONFRAMEWORK": framework.name,
        }.get(name)

    monkeypatch.setattr(runtime.sysconfig, "get_config_var", config_value)
    digest = runtime._interpreter_provenance(roots)
    assert len(digest) == 64


def test_executable_manifest_rejects_path_and_link_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "python"
    executable.write_bytes(b"executable")
    roots = (("runtime", tmp_path.resolve()),)
    original_reader = runtime._stable_regular_bytes

    def mutate_mode(path: Path, *, maximum_bytes: int) -> bytes:
        data = original_reader(path, maximum_bytes=maximum_bytes)
        executable.chmod(0o700)
        return data

    monkeypatch.setattr(runtime, "_stable_regular_bytes", mutate_mode)
    with pytest.raises(RuntimeProvenanceError, match="path changed"):
        runtime._executable_manifest(executable, roots)

    monkeypatch.setattr(runtime, "_stable_regular_bytes", original_reader)
    link = tmp_path / "link"
    link.symlink_to(executable.name)
    real_readlink = runtime.os.readlink
    calls = 0

    def changed_readlink(path: os.PathLike[str] | str) -> str:
        nonlocal calls
        value = real_readlink(path)
        if not isinstance(path, Path):
            return value
        calls += 1
        return value if calls == 1 else f"{value}-changed"

    monkeypatch.setattr(runtime.os, "readlink", changed_readlink)
    with pytest.raises(RuntimeProvenanceError, match="link changed"):
        runtime._executable_manifest(link, roots)

    with pytest.raises(RuntimeProvenanceError, match="cannot be read"):
        runtime._executable_manifest(tmp_path / "absent", roots)


def test_source_tree_census_handles_nested_content_and_rejects_unsafe_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "source"
    nested = root / "nested"
    nested.mkdir(parents=True)
    (nested / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    assert len(runtime._tree_provenance(root)) == 64

    with pytest.raises(RuntimeProvenanceError, match="cannot be resolved"):
        runtime._tree_provenance(tmp_path / "absent")
    regular = tmp_path / "regular"
    regular.write_text("data", encoding="utf-8")
    with pytest.raises(RuntimeProvenanceError, match="not a directory"):
        runtime._tree_provenance(regular)

    unsafe_root = tmp_path / "unsafe"
    unsafe_root.mkdir()
    (unsafe_root / "link").symlink_to(regular)
    with pytest.raises(RuntimeProvenanceError, match="nonregular"):
        runtime._tree_provenance(unsafe_root)

    monkeypatch.setattr(runtime, "_MAX_SOURCE_ENTRIES", 0)
    with pytest.raises(RuntimeProvenanceError, match="entry bound"):
        runtime._tree_provenance(root)
    monkeypatch.setattr(runtime, "_MAX_SOURCE_ENTRIES", 4096)
    monkeypatch.setattr(runtime, "_MAX_SOURCE_BYTES", 0)
    with pytest.raises(RuntimeProvenanceError, match="byte bound"):
        runtime._tree_provenance(root)


def test_source_tree_wraps_enumeration_and_inspection_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "source"
    root.mkdir()

    def broken_scandir(_path: Path) -> Any:
        raise OSError("synthetic scandir failure")

    monkeypatch.setattr(runtime.os, "scandir", broken_scandir)
    with pytest.raises(RuntimeProvenanceError, match="cannot be enumerated"):
        runtime._tree_provenance(root)

    class BrokenEntry:
        name = "broken"

        def stat(self, *, follow_symlinks: bool) -> os.stat_result:
            assert not follow_symlinks
            raise OSError("synthetic stat failure")

    class Scan:
        def __enter__(self) -> list[BrokenEntry]:
            return [BrokenEntry()]

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(runtime.os, "scandir", lambda _path: Scan())
    with pytest.raises(RuntimeProvenanceError, match="cannot be inspected"):
        runtime._tree_provenance(root)


def test_fieldtrue_source_must_match_selected_repository(tmp_path: Path) -> None:
    with pytest.raises(RuntimeProvenanceError, match="cannot be resolved"):
        runtime._fieldtrue_source_provenance(tmp_path)

    (tmp_path / "src" / "fieldtrue").mkdir(parents=True)
    with pytest.raises(RuntimeProvenanceError, match="outside the selected"):
        runtime._fieldtrue_source_provenance(tmp_path)

    repo = Path(__file__).resolve().parents[2]
    assert len(runtime._fieldtrue_source_provenance(repo)) == 64


def test_lock_graph_selects_transitive_runtime_dependencies() -> None:
    document = _lock(
        "[[package]]\n"
        'name = "alpha"\n'
        'version = "1.0"\n'
        'dependencies = [{ name = "beta", version = "2.0" }]\n'
        "[[package]]\n"
        'name = "beta"\n'
        'version = "2.0"\n'
        "dependencies = []\n"
        "[[package]]\n"
        'name = "skipped"\n'
        'version = "9.0"\n',
        (
            '[{ name = "alpha" }, { name = "alpha" }, '
            '{ name = "skipped", marker = "python_version < \'1\'" }]'
        ),
    )
    assert runtime._locked_runtime_dependencies(document) == (
        ("alpha", "1.0"),
        ("beta", "2.0"),
    )


@pytest.mark.parametrize(
    ("document", "message"),
    [
        (b"\xff", "canonical UTF-8 TOML"),
        (b"not = [valid", "canonical UTF-8 TOML"),
        (b"version = 2\npackage = []\n", "unsupported structure"),
        (b"version = 1\npackage = {}\n", "unsupported structure"),
        (b"version = 1\npackage = [1]\n", "package row is invalid"),
        (
            b'version = 1\n[[package]]\nname = "other"\nversion = "1"\n',
            "one local fieldtrue root",
        ),
        (
            b'version = 1\n[[package]]\nname = "fieldtrue"\nsource = { editable = "." }\n',
            "omits fieldtrue runtime dependencies",
        ),
    ],
)
def test_lock_graph_rejects_malformed_roots(document: bytes, message: str) -> None:
    with pytest.raises(RuntimeProvenanceError, match=message):
        runtime._locked_runtime_dependencies(document)


@pytest.mark.parametrize(
    ("dependencies", "packages", "message"),
    [
        ("[1]", "", "edge is invalid"),
        ("[{}]", "", "omits a package name"),
        ('[{ name = "missing" }]', "", "does not resolve uniquely"),
        (
            '[{ name = "duplicate" }]',
            "[[package]]\n"
            'name = "duplicate"\nversion = "1"\n'
            "[[package]]\n"
            'name = "DUPLICATE"\nversion = "1"\n',
            "does not resolve uniquely",
        ),
        (
            '[{ name = "bad" }]',
            '[[package]]\nname = "bad"\nversion = ""\n',
            "package version is invalid",
        ),
        (
            '[{ name = "bad" }]',
            '[[package]]\nname = "bad"\nversion = "1"\ndependencies = {}\n',
            "package dependencies are invalid",
        ),
    ],
)
def test_lock_graph_rejects_invalid_edges(
    dependencies: str,
    packages: str,
    message: str,
) -> None:
    with pytest.raises(RuntimeProvenanceError, match=message):
        runtime._locked_runtime_dependencies(_lock(packages, dependencies))


def test_lock_graph_rejects_conflicts_and_package_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conflict = _lock(
        '[[package]]\nname = "alpha"\nversion = "1"\n[[package]]\nname = "alpha"\nversion = "2"\n',
        '[{ name = "alpha", version = "1" }, { name = "alpha", version = "2" }]',
    )
    with pytest.raises(RuntimeProvenanceError, match="conflicting"):
        runtime._locked_runtime_dependencies(conflict)

    monkeypatch.setattr(runtime, "_MAX_DEPENDENCY_COUNT", 0)
    bounded = _lock('[[package]]\nname = "alpha"\nversion = "1"\n', '[{ name = "alpha" }]')
    with pytest.raises(RuntimeProvenanceError, match="package bound"):
        runtime._locked_runtime_dependencies(bounded)


@pytest.mark.parametrize(
    "marker",
    [1, "x" * 4097, "python_version ??? '3'"],
)
def test_dependency_markers_fail_closed(marker: object) -> None:
    with pytest.raises(RuntimeProvenanceError, match="marker"):
        runtime._marker_applies(marker)


@pytest.mark.parametrize(
    "digest",
    ["md5=value", "sha256=", "sha256=A", "sha256=" + "A" * 129],
)
def test_record_digest_rejects_unsupported_or_malformed_hashes(digest: str) -> None:
    with pytest.raises(RuntimeProvenanceError, match=r"(?:unsupported|malformed)"):
        runtime._record_digest(digest)


def test_distribution_metadata_requires_a_string_name() -> None:
    missing = SimpleNamespace(metadata={})
    with pytest.raises(RuntimeProvenanceError, match="omits its name"):
        runtime._distribution_name(missing)  # type: ignore[arg-type]
    invalid = SimpleNamespace(metadata={"Name": 17})
    with pytest.raises(RuntimeProvenanceError, match="name is invalid"):
        runtime._distribution_name(invalid)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "raw_path",
    ["", "/absolute.py", "package\\module.py", "package//module.py", "../../../lib/tool"],
)
def test_record_candidate_rejects_unsafe_lexical_paths(
    tmp_path: Path,
    raw_path: str,
) -> None:
    base = tmp_path / "runtime" / "lib" / "python3.12" / "site-packages"
    base.mkdir(parents=True)
    with pytest.raises(RuntimeProvenanceError, match=r"(?:path|traversal) is unsafe"):
        runtime._dependency_record_candidate(base, raw_path, runtime_prefix=tmp_path / "runtime")


def test_record_candidate_rejects_missing_escape_and_wrong_console_prefix(tmp_path: Path) -> None:
    prefix = tmp_path / "runtime"
    base = prefix / "lib" / "python3.12" / "site-packages"
    base.mkdir(parents=True)
    with pytest.raises(RuntimeProvenanceError, match="cannot be resolved"):
        runtime._dependency_record_candidate(base, "package/missing.py", runtime_prefix=prefix)

    outside = tmp_path / "outside.py"
    outside.write_text("outside", encoding="utf-8")
    (base / "escape.py").symlink_to(outside)
    with pytest.raises(RuntimeProvenanceError, match="escapes its installation root"):
        runtime._dependency_record_candidate(base, "escape.py", runtime_prefix=prefix)

    script = prefix / "bin" / "tool"
    script.parent.mkdir()
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    wrong_prefix = tmp_path / "wrong-runtime"
    wrong_prefix.mkdir()
    with pytest.raises(RuntimeProvenanceError, match="runtime bin"):
        runtime._dependency_record_candidate(
            base,
            "../../../bin/tool",
            runtime_prefix=wrong_prefix,
        )


def test_distribution_manifest_rejects_identity_and_record_census(
    tmp_path: Path,
) -> None:
    distribution, prefix, record = _write_distribution(tmp_path)
    roots = (("runtime", prefix.resolve()),)

    with pytest.raises(RuntimeProvenanceError, match="selected lock version"):
        runtime._distribution_manifest(
            distribution,
            expected_name="other",
            expected_version="1.0",
            roots=roots,
            runtime_prefix=prefix,
        )

    missing_files = SimpleNamespace(
        metadata=distribution.metadata,
        version=distribution.version,
        files=None,
    )
    with pytest.raises(RuntimeProvenanceError, match="no bounded RECORD"):
        runtime._distribution_manifest(
            missing_files,  # type: ignore[arg-type]
            expected_name="example-dependency",
            expected_version="1.0",
            roots=roots,
            runtime_prefix=prefix,
        )

    frozen = _frozen_distribution(distribution)
    record.write_bytes(b"\xff")
    with pytest.raises(RuntimeProvenanceError, match="not valid UTF-8 CSV"):
        runtime._distribution_manifest(
            frozen,  # type: ignore[arg-type]
            expected_name="example-dependency",
            expected_version="1.0",
            roots=roots,
            runtime_prefix=prefix,
        )


def test_distribution_manifest_rejects_record_rows_and_aggregate_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    distribution, prefix, record = _write_distribution(tmp_path)
    roots = (("runtime", prefix.resolve()),)
    original = record.read_text(encoding="utf-8")
    frozen = _frozen_distribution(distribution)

    record.write_text(original.rsplit("\n", 2)[0] + "\n", encoding="utf-8")
    with pytest.raises(RuntimeProvenanceError, match="census is inconsistent"):
        runtime._distribution_manifest(
            frozen,  # type: ignore[arg-type]
            expected_name="example-dependency",
            expected_version="1.0",
            roots=roots,
            runtime_prefix=prefix,
        )

    record.write_text("bad,row\n" * 3, encoding="utf-8")
    with pytest.raises(RuntimeProvenanceError, match="row is malformed"):
        runtime._distribution_manifest(
            frozen,  # type: ignore[arg-type]
            expected_name="example-dependency",
            expected_version="1.0",
            roots=roots,
            runtime_prefix=prefix,
        )

    rows = original.splitlines()
    record.write_text("\n".join([rows[0], rows[0], rows[2]]) + "\n", encoding="utf-8")
    with pytest.raises(RuntimeProvenanceError, match="path is unsafe"):
        runtime._distribution_manifest(
            frozen,  # type: ignore[arg-type]
            expected_name="example-dependency",
            expected_version="1.0",
            roots=roots,
            runtime_prefix=prefix,
        )

    record.write_text(original, encoding="utf-8")
    monkeypatch.setattr(runtime, "_MAX_DEPENDENCY_BYTES", 0)
    with pytest.raises(RuntimeProvenanceError, match="byte bound"):
        runtime._distribution_manifest(
            frozen,  # type: ignore[arg-type]
            expected_name="example-dependency",
            expected_version="1.0",
            roots=roots,
            runtime_prefix=prefix,
        )


def test_distribution_manifest_rejects_self_hash_size_and_final_census(tmp_path: Path) -> None:
    distribution, prefix, record = _write_distribution(tmp_path)
    roots = (("runtime", prefix.resolve()),)
    rows = record.read_text(encoding="utf-8").splitlines()
    frozen = _frozen_distribution(distribution)

    rows[-1] = f"{rows[-1].split(',')[0]},sha256=A,1"
    record.write_text("\n".join(rows) + "\n", encoding="utf-8")
    with pytest.raises(RuntimeProvenanceError, match="leave its own hash empty"):
        runtime._distribution_manifest(
            frozen,  # type: ignore[arg-type]
            expected_name="example-dependency",
            expected_version="1.0",
            roots=roots,
            runtime_prefix=prefix,
        )

    distribution, prefix, record = _write_distribution(tmp_path / "second")
    roots = (("runtime", prefix.resolve()),)
    rows = record.read_text(encoding="utf-8").splitlines()
    frozen = _frozen_distribution(distribution)
    parts = rows[0].split(",")
    rows[0] = f"{parts[0]},{parts[1]},not-a-size"
    record.write_text("\n".join(rows) + "\n", encoding="utf-8")
    with pytest.raises(RuntimeProvenanceError, match="RECORD size"):
        runtime._distribution_manifest(
            frozen,  # type: ignore[arg-type]
            expected_name="example-dependency",
            expected_version="1.0",
            roots=roots,
            runtime_prefix=prefix,
        )

    distribution, prefix, record = _write_distribution(tmp_path / "third")
    roots = (("runtime", prefix.resolve()),)
    frozen = _frozen_distribution(distribution)
    extra = Path(str(distribution.locate_file("extra.py")))
    extra.write_text("extra", encoding="utf-8")
    rows = record.read_text(encoding="utf-8").splitlines()
    rows[0] = f"extra.py,{_record_hash(extra.read_bytes())},{extra.stat().st_size}"
    record.write_text("\n".join(rows) + "\n", encoding="utf-8")
    with pytest.raises(RuntimeProvenanceError, match="census is inconsistent"):
        runtime._distribution_manifest(
            frozen,  # type: ignore[arg-type]
            expected_name="example-dependency",
            expected_version="1.0",
            roots=roots,
            runtime_prefix=prefix,
        )
