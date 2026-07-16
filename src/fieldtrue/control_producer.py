"""Child-only producer for fixture admission-control authority bundles.

This module is imported only by the isolated child prepared by the committed launcher. The child
authenticates its environment after import. Canonical production authority remains disabled until a
separately approved V2 suite and key-custody boundary exist.
"""

from __future__ import annotations

import ctypes
import errno
import importlib.metadata
import os
import platform
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tomllib
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from nacl.signing import SigningKey

import fieldtrue.runner_trust as runner_trust
from fieldtrue.acquisition import (
    _ITER001_CANONICAL_TRUST_ANCHOR_PUBLIC_KEY,
    _REQUIRED_CONTROL_IDS,
    AcquisitionContract,
    AdmissionControlResult,
    AdmissionControlSuiteReceipt,
    AttestationSubjectKind,
    _acquisition_source_closure,
    attestation_subject_hash,
    issue_attestation,
)
from fieldtrue.canonical import (
    atomic_write,
    canonical_json_pretty,
    sha256_bytes,
    sha256_value,
)
from fieldtrue.control_authority import (
    _SOURCE_PATHS,
    ControlExecutionManifest,
    ControlManifestEntry,
    GitBoundSource,
    _artifact_binding,
    _assert_clean_repo,
    _authenticated_runner_is_unchanged,
    _git_bound_source,
    _git_identity,
    _run_control,
    _run_git,
)
from fieldtrue.control_protocol import (
    CONTROL_PRODUCER_KEY_PATH,
    CONTROL_PRODUCER_PLATFORM_ENVIRONMENT,
    CONTROL_PRODUCER_RECEIPT_PATH,
    CONTROL_PRODUCER_SNAPSHOT_PATHS,
    MAX_CONTROL_PRODUCER_REQUEST_BYTES,
    ControlAuthorityError,
    ControlProducerRequest,
    ControlProducerResponse,
)
from fieldtrue.git_trust import git_environment, trusted_repository_git
from fieldtrue.runner_trust import (
    PINNED_PYTHON_ARTIFACTS,
    RUNNER_PYTHON_FULL_VERSION,
    AuthenticatedRunner,
    RunnerTrustError,
)

_RUNNER_ROOT_DISTRIBUTIONS = frozenset({"certifi", "networkx", "pydantic", "pynacl", "pytest"})
_EXPECTED_ENVIRONMENT_KEYS = frozenset(
    {
        "HOME",
        "LANG",
        "LC_ALL",
        "NO_COLOR",
        "PATH",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONHASHSEED",
        "TEMP",
        "TMP",
        "TMPDIR",
        "TZ",
    }
    | {name for name, _value in CONTROL_PRODUCER_PLATFORM_ENVIRONMENT}
)
_SAFE_PATH = "/usr/bin:/bin"
_BUNDLE_DIRECTORY_NAME = "admission-controls"
_CONTRACT_PATH = "protocol/acquisition/iter001_contract.json"
_KEY_DIRECTORY_PARTS = (".local", "keys")
_KEY_FILE_NAME = Path(CONTROL_PRODUCER_KEY_PATH).name
_STABLE_STAT_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_nlink",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
    "st_uid",
    "st_gid",
)


def _same_stat(first: os.stat_result, second: os.stat_result) -> bool:
    return all(getattr(first, field) == getattr(second, field) for field in _STABLE_STAT_FIELDS)


def _same_directory_identity(first: os.stat_result, second: os.stat_result) -> bool:
    fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid")
    return all(getattr(first, field) == getattr(second, field) for field in fields)


def _directory_flags() -> int:
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise ControlAuthorityError("descriptor-relative producer paths are unsupported")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _directory_is_trusted(metadata: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and not metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    )


def _open_trusted_directory(path: Path) -> int:
    try:
        descriptor = os.open(path, _directory_flags())
        metadata = os.fstat(descriptor)
        current = path.stat(follow_symlinks=False)
    except OSError as error:
        _close_optional_descriptor(locals().get("descriptor"))
        raise ControlAuthorityError("producer directory boundary is unavailable") from error
    if not _directory_is_trusted(metadata) or not _same_stat(metadata, current):
        os.close(descriptor)
        raise ControlAuthorityError("producer directory boundary is untrusted")
    return descriptor


def _close_optional_descriptor(descriptor: object) -> None:
    if isinstance(descriptor, int):
        with suppress(OSError):
            os.close(descriptor)


def _open_directory_at(parent_descriptor: int, name: str) -> int:
    if not name or "/" in name or name in {".", ".."}:
        raise ControlAuthorityError("producer directory component is invalid")
    try:
        descriptor = os.open(name, _directory_flags(), dir_fd=parent_descriptor)
        opened = os.fstat(descriptor)
        current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError as error:
        _close_optional_descriptor(locals().get("descriptor"))
        raise ControlAuthorityError("producer directory component is unavailable") from error
    if not _directory_is_trusted(opened) or not _same_stat(opened, current):
        os.close(descriptor)
        raise ControlAuthorityError("producer directory component is untrusted")
    return descriptor


def _read_existing_key(repo: Path, expected_public_key: str) -> SigningKey:
    repo_descriptor = _open_trusted_directory(repo)
    local_descriptor: int | None = None
    keys_descriptor: int | None = None
    key_descriptor: int | None = None
    seed = bytearray()
    try:
        local_descriptor = _open_directory_at(repo_descriptor, _KEY_DIRECTORY_PARTS[0])
        keys_descriptor = _open_directory_at(local_descriptor, _KEY_DIRECTORY_PARTS[1])
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        key_descriptor = os.open(_KEY_FILE_NAME, flags, dir_fd=keys_descriptor)
        opened = os.fstat(key_descriptor)
        current = os.stat(_KEY_FILE_NAME, dir_fd=keys_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or opened.st_size != 32
            or not _same_stat(opened, current)
        ):
            raise ControlAuthorityError("producer signing key boundary is untrusted")
        while len(seed) <= 32:
            chunk = os.read(key_descriptor, 33 - len(seed))
            if not chunk:
                break
            seed.extend(chunk)
        settled = os.fstat(key_descriptor)
        final = os.stat(_KEY_FILE_NAME, dir_fd=keys_descriptor, follow_symlinks=False)
        if len(seed) != 32 or not _same_stat(opened, settled) or not _same_stat(settled, final):
            raise ControlAuthorityError("producer signing key changed during read")
        key = SigningKey(bytes(seed))
        if key.verify_key.encode().hex() != expected_public_key:
            raise ControlAuthorityError("producer signing key differs from the contract")
        return key
    except OSError as error:
        raise ControlAuthorityError("producer signing key cannot be opened") from error
    finally:
        for index in range(len(seed)):
            seed[index] = 0
        for descriptor in (key_descriptor, keys_descriptor, local_descriptor, repo_descriptor):
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)


def _canonical_distribution_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _reconstruct_runner() -> AuthenticatedRunner:
    module_path = Path(__file__).resolve(strict=True)
    snapshot_root = module_path.parents[2]
    root = snapshot_root.parent
    source_root = snapshot_root / "src"
    site_packages = root / "authenticated-site-packages"
    scratch_root = root / "runner-scratch"
    interpreter_root = Path(sys.base_prefix).resolve(strict=True)
    python_path = Path(sys.executable).resolve(strict=True)
    if (
        sys.flags.isolated != 1
        or sys.flags.no_site != 1
        or sys.flags.dont_write_bytecode != 1
        or sys.flags.safe_path is not True
        or tuple(Path(item).resolve(strict=True) for item in sys.path[:2])
        != (source_root.resolve(strict=True), site_packages.resolve(strict=True))
        or not python_path.is_relative_to(interpreter_root)
        or not interpreter_root.is_relative_to(root.resolve(strict=True))
        or set(os.environ) != _EXPECTED_ENVIRONMENT_KEYS
        or any(
            os.environ.get(name) != value for name, value in CONTROL_PRODUCER_PLATFORM_ENVIRONMENT
        )
        or os.environ.get("PATH") != _SAFE_PATH
        or any(os.environ.get(name) != str(scratch_root) for name in ("TEMP", "TMP", "TMPDIR"))
    ):
        raise ControlAuthorityError("producer child runtime is not isolated")

    expected_origins = {
        "fieldtrue.control_producer": "control_producer.py",
        "fieldtrue.control_authority": "control_authority.py",
        "fieldtrue.control_protocol": "control_protocol.py",
        "fieldtrue.runner_trust": "runner_trust.py",
    }
    for module_name, relative in expected_origins.items():
        module = sys.modules.get(module_name)
        origin = getattr(module, "__file__", None) if module is not None else None
        if not isinstance(origin, str) or Path(origin).resolve(strict=True) != (
            source_root / "fieldtrue" / relative
        ).resolve(strict=True):
            raise ControlAuthorityError("producer child module origin is unexpected")

    uv_path = root / "authenticated-uv" / "uv"
    uv = runner_trust.resolve_pinned_uv(uv_path, required_root=uv_path.parent)
    python = runner_trust.bind_executable(python_path, required_root=interpreter_root)
    lock_bytes = runner_trust.stable_regular_bytes(
        snapshot_root / "uv.lock", maximum_bytes=16 * 1024 * 1024
    )
    python_artifact = PINNED_PYTHON_ARTIFACTS.get(
        (platform.system().casefold(), platform.machine().casefold())
    )
    if uv is None or python is None or lock_bytes is None or python_artifact is None:
        raise ControlAuthorityError("producer runner identity is incomplete")
    try:
        lock = tomllib.loads(lock_bytes.decode("utf-8"))
        wheels = runner_trust.resolve_locked_wheels(
            lock, root_distributions=_RUNNER_ROOT_DISTRIBUTIONS
        )
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, RunnerTrustError) as error:
        raise ControlAuthorityError("producer dependency lock is invalid") from error
    distribution_versions = tuple(sorted((wheel.distribution, wheel.version) for wheel in wheels))
    installed: list[tuple[str, str]] = []
    for distribution in importlib.metadata.distributions(path=[str(site_packages)]):
        name = distribution.metadata["Name"]
        if not isinstance(name, str):
            raise ControlAuthorityError("producer distribution metadata is incomplete")
        installed.append((_canonical_distribution_name(name), distribution.version))
    if tuple(sorted(installed)) != distribution_versions:
        raise ControlAuthorityError("producer distributions differ from the dependency lock")
    artifact_set_sha256 = sha256_value(
        {
            "schema_version": "fieldtrue.authenticated-runner-artifacts.v1",
            "lock_sha256": sha256_bytes(lock_bytes),
            "wheels": [
                {
                    "distribution": wheel.distribution,
                    "filename": wheel.filename,
                    "sha256": wheel.sha256,
                    "size": wheel.size,
                    "url": wheel.url,
                    "version": wheel.version,
                }
                for wheel in wheels
            ],
        }
    )
    environment_sha256 = runner_trust.tree_digest(root, excluded_relative_paths=("runner-scratch",))
    if environment_sha256 is None:
        raise ControlAuthorityError("producer runner tree cannot be bound")
    runner = AuthenticatedRunner(
        root=root,
        snapshot_root=snapshot_root,
        python_path=python_path,
        site_packages=site_packages,
        interpreter_root=interpreter_root,
        scratch_root=scratch_root,
        uv=uv,
        python=python,
        python_artifact_sha256=python_artifact[3],
        host_tool=runner_trust.host_tool_binding(),
        python_version=RUNNER_PYTHON_FULL_VERSION,
        lock_sha256=sha256_bytes(lock_bytes),
        artifact_set_sha256=artifact_set_sha256,
        environment_sha256=environment_sha256,
        excluded_tree_paths=("runner-scratch",),
        distribution_versions=distribution_versions,
    )
    if not runner_trust.runner_is_unchanged(runner):
        raise ControlAuthorityError("producer runner failed independent rebinding")
    return runner


def _verify_source_closure(
    repo: Path,
    runner: AuthenticatedRunner,
    commit: str,
    sources: tuple[GitBoundSource, ...],
) -> tuple[str, int]:
    _verify_exact_snapshot(repo, runner.snapshot_root, commit)
    source_by_name = {item.name: item for item in sources}
    validator = source_by_name["validator"]
    git = trusted_repository_git(repo)
    closure = _acquisition_source_closure(
        git,
        repo,
        git_environment(),
        authority_commit=commit,
        repository_head=commit,
        expected_validator_blob=validator.git_blob,
        expected_validator_sha256=validator.sha256,
        working_source_root=runner.snapshot_root,
    )
    for relative, _mode, _blob, digest, size in closure.sources:
        snapshot_bytes = runner_trust.stable_regular_bytes(
            runner.snapshot_root.joinpath(*Path(relative).parts),
            maximum_bytes=runner_trust.MAX_RUNNER_FILE_BYTES,
        )
        if (
            snapshot_bytes is None
            or len(snapshot_bytes) != size
            or sha256_bytes(snapshot_bytes) != digest
        ):
            raise ControlAuthorityError("producer snapshot differs from committed source closure")
    return closure.closure_sha256, len(closure.sources)


def _verify_exact_snapshot(repo: Path, snapshot_root: Path, commit: str) -> None:
    try:
        raw = _run_git(
            repo,
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            commit,
            "--",
            *CONTROL_PRODUCER_SNAPSHOT_PATHS,
            text=False,
        )
    except (ControlAuthorityError, OSError, ValueError) as error:
        raise ControlAuthorityError(
            "producer snapshot inventory cannot be reconstructed"
        ) from error
    if not isinstance(raw, bytes):
        raise ControlAuthorityError("producer snapshot inventory is invalid")
    records = raw.split(b"\0")
    if records[-1:] != [b""] or len(records) > runner_trust.MAX_RUNNER_TREE_ENTRIES:
        raise ControlAuthorityError("producer snapshot inventory is outside bounds")

    expected_files: dict[str, tuple[int, bytes]] = {}
    expected_directories: set[str] = set()
    total_bytes = 0
    try:
        for record in records[:-1]:
            header, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id = header.decode("ascii").split(" ")
            relative = raw_path.decode("utf-8")
            pure = PurePosixPath(relative)
            if (
                mode not in {"100644", "100755"}
                or object_type != "blob"
                or pure.is_absolute()
                or ".." in pure.parts
                or relative != pure.as_posix()
                or relative in expected_files
                or not any(
                    relative == prefix or relative.startswith(f"{prefix}/")
                    for prefix in CONTROL_PRODUCER_SNAPSHOT_PATHS
                )
            ):
                raise ControlAuthorityError("producer snapshot Git inventory is unsafe")
            payload = _run_git(repo, "cat-file", "blob", object_id, text=False)
            if not isinstance(payload, bytes) or len(payload) > runner_trust.MAX_RUNNER_FILE_BYTES:
                raise ControlAuthorityError("producer snapshot Git blob is outside bounds")
            total_bytes += len(payload)
            if total_bytes > runner_trust.MAX_RUNNER_TREE_BYTES:
                raise ControlAuthorityError("producer snapshot Git tree is outside bounds")
            expected_files[relative] = (0o500 if mode == "100755" else 0o400, payload)
            expected_directories.update(
                PurePosixPath(*pure.parts[:index]).as_posix() for index in range(1, len(pure.parts))
            )
    except (UnicodeDecodeError, ValueError) as error:
        raise ControlAuthorityError("producer snapshot Git inventory is malformed") from error

    observed_files: set[str] = set()
    observed_directories: set[str] = set()
    for path in snapshot_root.rglob("*"):
        relative = path.relative_to(snapshot_root).as_posix()
        try:
            metadata = path.lstat()
        except OSError as error:
            raise ControlAuthorityError("producer snapshot entry cannot be inspected") from error
        if stat.S_ISDIR(metadata.st_mode):
            if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
                raise ControlAuthorityError("producer snapshot directory is untrusted")
            observed_directories.add(relative)
            continue
        expected = expected_files.get(relative)
        if expected is None or not stat.S_ISREG(metadata.st_mode):
            raise ControlAuthorityError("producer snapshot contains an unexpected entry")
        expected_mode, expected_bytes = expected
        actual = runner_trust.stable_regular_bytes(
            path,
            maximum_bytes=runner_trust.MAX_RUNNER_FILE_BYTES,
        )
        if (
            actual != expected_bytes
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != expected_mode
        ):
            raise ControlAuthorityError("producer snapshot file differs from committed authority")
        observed_files.add(relative)
    if observed_files != set(expected_files) or observed_directories != expected_directories:
        raise ControlAuthorityError("producer snapshot census differs from committed authority")


def _verify_preregistration_ancestry(
    repo: Path, contract: AcquisitionContract, commit: str
) -> None:
    try:
        result = subprocess_run_git_ancestry(repo, contract.preregistration_commit, commit)
    except (OSError, subprocess.SubprocessError) as error:
        raise ControlAuthorityError(
            "producer preregistration ancestry cannot be checked"
        ) from error
    if result != 0:
        raise ControlAuthorityError("preregistration commit is not control-execution ancestry")


def _committed_bytes(repo: Path, commit: str, relative_path: str) -> bytes:
    try:
        blob = _run_git(repo, "rev-parse", f"{commit}:{relative_path}")
        payload = _run_git(repo, "cat-file", "blob", str(blob), text=False)
    except (ControlAuthorityError, OSError, ValueError) as error:
        raise ControlAuthorityError("producer committed authority bytes cannot be read") from error
    if not isinstance(payload, bytes):
        raise ControlAuthorityError("producer committed authority bytes are invalid")
    return payload


def _load_execution_contract(repo: Path, commit: str) -> AcquisitionContract:
    committed = _committed_bytes(repo, commit, _CONTRACT_PATH)
    working = runner_trust.stable_regular_bytes(
        repo / _CONTRACT_PATH,
        maximum_bytes=runner_trust.MAX_RUNNER_FILE_BYTES,
    )
    try:
        contract = AcquisitionContract.model_validate_json(committed, strict=True)
    except ValueError as error:
        raise ControlAuthorityError("producer execution contract is invalid") from error
    if working != committed or canonical_json_pretty(contract) != committed:
        raise ControlAuthorityError("producer execution contract differs from committed authority")
    return contract


def _verify_preregistration_bytes(
    repo: Path,
    contract: AcquisitionContract,
    commit: str,
) -> None:
    execution_bytes = _committed_bytes(repo, commit, contract.preregistration_path)
    frozen_bytes = _committed_bytes(
        repo,
        contract.preregistration_commit,
        contract.preregistration_path,
    )
    if (
        execution_bytes != frozen_bytes
        or sha256_bytes(execution_bytes) != contract.preregistration_sha256
    ):
        raise ControlAuthorityError("producer preregistration bytes differ from frozen authority")


def subprocess_run_git_ancestry(repo: Path, ancestor: str, descendant: str) -> int:
    completed = subprocess.run(  # noqa: S603 - trusted Git and validated object identifiers
        (trusted_repository_git(repo), "merge-base", "--is-ancestor", ancestor, descendant),
        cwd=repo,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=git_environment(),
        timeout=10,
    )
    return completed.returncode


def _rename_no_replace_at(parent_descriptor: int, source: str, target: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        result = libc.renameatx_np(
            parent_descriptor,
            os.fsencode(source),
            parent_descriptor,
            os.fsencode(target),
            0x00000004,
        )
    elif sys.platform.startswith("linux"):
        result = libc.renameat2(
            parent_descriptor,
            os.fsencode(source),
            parent_descriptor,
            os.fsencode(target),
            1,
        )
    else:
        raise ControlAuthorityError("descriptor-relative publication is unsupported")
    if result != 0:
        number = ctypes.get_errno()
        if number in (errno.EEXIST, errno.ENOTEMPTY):
            raise FileExistsError(target)
        raise OSError(number, os.strerror(number), target)


def _bundle_file_census(staging: Path) -> tuple[str, ...]:
    observed: list[str] = []
    for path in staging.rglob("*"):
        relative = path.relative_to(staging).as_posix()
        if path.is_symlink() or (not path.is_dir() and not path.is_file()):
            raise ControlAuthorityError("producer staging contains an unsafe artifact")
        if path.is_file():
            observed.append(relative)
    return tuple(sorted(observed))


def _produce_fixture_bundle(
    repo: Path,
    runner: AuthenticatedRunner,
    *,
    expected_commit: str,
    expected_tree: str,
    timeout_seconds: int,
) -> tuple[Path, str, str, str]:
    _assert_clean_repo(repo)
    commit, tree = _git_identity(repo)
    if (commit, tree) != (expected_commit, expected_tree):
        raise ControlAuthorityError("producer Git identity differs from the launcher request")
    sources = tuple(_git_bound_source(repo, commit, name, path) for name, path in _SOURCE_PATHS)
    contract = _load_execution_contract(repo, commit)
    if (
        contract.authority_profile != "test_fixture"
        or contract.control_authority_status != "test_fixture"
    ):
        raise ControlAuthorityError("canonical control production is disabled pending V2 authority")
    if contract.trust_anchor_public_key == _ITER001_CANONICAL_TRUST_ANCHOR_PUBLIC_KEY:
        raise ControlAuthorityError("fixture control production cannot use the canonical trust key")
    _verify_preregistration_ancestry(repo, contract, commit)
    _verify_preregistration_bytes(repo, contract, commit)
    source_closure_sha256, source_file_count = _verify_source_closure(repo, runner, commit, sources)

    repo_descriptor = _open_trusted_directory(repo)
    local_descriptor = _open_directory_at(repo_descriptor, ".local")
    staging_name = f".{_BUNDLE_DIRECTORY_NAME}.tmp-{secrets.token_hex(16)}"
    try:
        try:
            os.stat(_BUNDLE_DIRECTORY_NAME, dir_fd=local_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError(repo / ".local" / _BUNDLE_DIRECTORY_NAME)
        os.mkdir(staging_name, mode=0o700, dir_fd=local_descriptor)
        staging = repo / ".local" / staging_name
        staging_descriptor = os.open(staging_name, _directory_flags(), dir_fd=local_descriptor)
        published = False
        try:
            started_at = datetime.now(UTC)
            results: list[AdmissionControlResult] = []
            entries: list[ControlManifestEntry] = []
            for control_id in _REQUIRED_CONTROL_IDS:
                if not _authenticated_runner_is_unchanged(runner):
                    raise ControlAuthorityError("producer runner changed before control")
                result, entry = _run_control(
                    staging,
                    commit=commit,
                    tree=tree,
                    control_id=control_id,
                    runner=runner,
                    timeout_seconds=timeout_seconds,
                )
                if not _authenticated_runner_is_unchanged(runner):
                    raise ControlAuthorityError("producer runner changed after control")
                results.append(result)
                entries.append(entry)
            _assert_clean_repo(repo)
            if _git_identity(repo) != (commit, tree):
                raise ControlAuthorityError("repository identity changed during controls")
            rebound_sources = tuple(
                _git_bound_source(repo, commit, name, path) for name, path in _SOURCE_PATHS
            )
            if rebound_sources != sources:
                raise ControlAuthorityError("producer sources changed during controls")
            if _load_execution_contract(repo, commit) != contract:
                raise ControlAuthorityError("producer execution contract changed during controls")
            if _verify_source_closure(repo, runner, commit, sources) != (
                source_closure_sha256,
                source_file_count,
            ):
                raise ControlAuthorityError("producer source closure changed during controls")
            if not _authenticated_runner_is_unchanged(runner):
                raise ControlAuthorityError("producer runner changed before assembly")
            finished_at = datetime.now(UTC)
            manifest = ControlExecutionManifest(
                suite_id="iter001-admission-controls-v1",
                execution_commit=commit,
                execution_tree=tree,
                started_at=started_at,
                finished_at=finished_at,
                repository_clean_before=True,
                repository_clean_after=True,
                dependency_mode="lock-hash-authenticated-wheels",
                uv_executable=str(runner.uv.executable.resolved_path),
                uv_executable_sha256=runner.uv.executable.sha256,
                uv_version=runner.uv.version,
                python_executable_sha256=runner.python.sha256,
                python_version=RUNNER_PYTHON_FULL_VERSION,
                runner_environment_sha256=runner.environment_sha256,
                artifact_set_sha256=runner.artifact_set_sha256,
                source_closure_sha256=source_closure_sha256,
                source_file_count=source_file_count,
                environment_policy=(
                    "committed-source-snapshot",
                    "complete-package-source-closure",
                    "fresh-isolated-fixture-producer",
                    "fresh-private-managed-python",
                    "lock-hash-authenticated-wheels",
                    "isolated-python-no-site",
                    "explicit-environment-allowlist",
                    "pytest-plugin-autoload-disabled",
                    "runner-rebound-before-and-after-each-control",
                ),
                sources=sources,
                controls=tuple(entries),
            )
            manifest_path = staging / "execution_manifest.json"
            atomic_write(manifest_path, canonical_json_pretty(manifest), mode=0o444)
            manifest_binding = _artifact_binding(staging, manifest_path)
            source_by_name = {item.name: item for item in sources}
            receipt_body: dict[str, Any] = {
                "schema_version": "fieldtrue.admission-control-suite-receipt.v2",
                "suite_id": "iter001-admission-controls-v1",
                "authority_profile": "test_fixture",
                "acquisition_contract_git_blob": source_by_name["acquisition_contract"].git_blob,
                "acquisition_contract_sha256": source_by_name["acquisition_contract"].sha256,
                "validator_git_blob": source_by_name["validator"].git_blob,
                "validator_source_sha256": source_by_name["validator"].sha256,
                "fixture_builder_git_blob": source_by_name["fixture_builder"].git_blob,
                "fixture_builder_sha256": source_by_name["fixture_builder"].sha256,
                "control_test_git_blob": source_by_name["control_test"].git_blob,
                "control_test_sha256": source_by_name["control_test"].sha256,
                "generator_git_blob": source_by_name["generator"].git_blob,
                "generator_sha256": source_by_name["generator"].sha256,
                "dependency_lock_git_blob": source_by_name["dependency_lock"].git_blob,
                "dependency_lock_sha256": source_by_name["dependency_lock"].sha256,
                "execution_commit": commit,
                "execution_tree": tree,
                "execution_manifest": manifest_binding.model_dump(mode="json"),
                "executed_at": finished_at,
                "controls": [result.model_dump(mode="json") for result in results],
            }
            _assert_clean_repo(repo)
            if _git_identity(repo) != (commit, tree):
                raise ControlAuthorityError("repository identity changed before key access")
            if _verify_source_closure(repo, runner, commit, sources) != (
                source_closure_sha256,
                source_file_count,
            ):
                raise ControlAuthorityError("producer source closure changed before key access")
            if _load_execution_contract(repo, commit) != contract:
                raise ControlAuthorityError("producer execution contract changed before key access")
            key = _read_existing_key(repo, contract.trust_anchor_public_key)
            attestation = issue_attestation(
                key,
                attestation_id="iter001-admission-controls-fixture-attestation",
                signer_id="iter001-control-fixture-root",
                subject_kind=AttestationSubjectKind.CONTROL_SUITE,
                subject_sha256=attestation_subject_hash(
                    AttestationSubjectKind.CONTROL_SUITE, receipt_body
                ),
                issued_at=finished_at,
            )
            del key
            receipt = AdmissionControlSuiteReceipt.model_validate(
                {**receipt_body, "attestation": attestation.model_dump(mode="json")}
            )
            receipt_path = staging / "control_suite_receipt.json"
            receipt_bytes = canonical_json_pretty(receipt)
            atomic_write(receipt_path, receipt_bytes, mode=0o444)
            expected_files = tuple(
                sorted(
                    (
                        "execution_manifest.json",
                        "control_suite_receipt.json",
                        *(f"controls/{control_id}.json" for control_id in _REQUIRED_CONTROL_IDS),
                    )
                )
            )
            if _bundle_file_census(staging) != expected_files:
                raise ControlAuthorityError("producer bundle file census is not exact")
            os.fsync(staging_descriptor)
            opened_staging = os.fstat(staging_descriptor)
            current_staging = os.stat(staging_name, dir_fd=local_descriptor, follow_symlinks=False)
            if not _same_stat(opened_staging, current_staging):
                raise ControlAuthorityError("producer staging directory changed before publication")
            _rename_no_replace_at(local_descriptor, staging_name, _BUNDLE_DIRECTORY_NAME)
            try:
                os.fsync(local_descriptor)
                published_metadata = os.stat(
                    _BUNDLE_DIRECTORY_NAME,
                    dir_fd=local_descriptor,
                    follow_symlinks=False,
                )
                if not _same_directory_identity(opened_staging, published_metadata):
                    raise ControlAuthorityError("published producer directory differs from staging")
            except BaseException:
                _rename_no_replace_at(
                    local_descriptor,
                    _BUNDLE_DIRECTORY_NAME,
                    staging_name,
                )
                os.fsync(local_descriptor)
                raise
            published = True
            final_receipt = repo / CONTROL_PRODUCER_RECEIPT_PATH
            return final_receipt, commit, tree, sha256_bytes(receipt_bytes)
        finally:
            os.close(staging_descriptor)
            if not published:
                shutil.rmtree(repo / ".local" / staging_name, ignore_errors=True)
    finally:
        os.close(local_descriptor)
        os.close(repo_descriptor)


def _read_request() -> tuple[ControlProducerRequest, bytes]:
    raw = sys.stdin.buffer.read(MAX_CONTROL_PRODUCER_REQUEST_BYTES + 1)
    if not raw or len(raw) > MAX_CONTROL_PRODUCER_REQUEST_BYTES:
        raise ControlAuthorityError("producer request size is invalid")
    try:
        request = ControlProducerRequest.model_validate_json(raw, strict=True)
    except ValueError as error:
        raise ControlAuthorityError("producer request is invalid") from error
    if canonical_json_pretty(request) != raw:
        raise ControlAuthorityError("producer request is not canonical")
    return request, raw


def producer_child_main() -> int:
    try:
        request, raw_request = _read_request()
    except (ControlAuthorityError, OSError):
        return 2
    request_sha256 = sha256_bytes(raw_request)
    try:
        repo = Path(request.repository_root).resolve(strict=True)
        if str(repo) != request.repository_root:
            raise ControlAuthorityError("producer repository changed during resolution")
        runner = _reconstruct_runner()
        receipt, commit, tree, receipt_sha256 = _produce_fixture_bundle(
            repo,
            runner,
            expected_commit=request.execution_commit,
            expected_tree=request.execution_tree,
            timeout_seconds=request.timeout_seconds,
        )
        if receipt != repo / CONTROL_PRODUCER_RECEIPT_PATH:
            raise ControlAuthorityError("producer published an unexpected receipt path")
        response = ControlProducerResponse(
            request_id=request.request_id,
            request_sha256=request_sha256,
            status="published",
            execution_commit=commit,
            execution_tree=tree,
            receipt_sha256=receipt_sha256,
            published_path=".local/admission-controls/control_suite_receipt.json",
            control_count=22,
        )
        status = 0
    except Exception:
        response = ControlProducerResponse(
            request_id=request.request_id,
            request_sha256=request_sha256,
            status="rejected",
            failure_code="producer-rejected",
        )
        status = 1
    try:
        sys.stdout.buffer.write(canonical_json_pretty(response))
        sys.stdout.buffer.flush()
    except OSError:
        return 3
    return status


if __name__ == "__main__":
    raise SystemExit(producer_child_main())
