from __future__ import annotations

import io
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from pydantic import ValidationError

import fieldtrue.control_authority as authority
import fieldtrue.control_launcher as launcher
import fieldtrue.control_producer as producer
from fieldtrue.acquisition import AcquisitionContract
from fieldtrue.canonical import canonical_json_pretty, read_json, sha256_bytes
from fieldtrue.control_protocol import (
    CONTROL_PRODUCER_FAILURE_CODE,
    CONTROL_PRODUCER_KEY_PATH,
    CONTROL_PRODUCER_RECEIPT_PATH,
    CONTROL_PRODUCER_RUNNER_ACQUISITION_FAILURE_CODE,
    ControlAuthorityError,
    ControlProducerRequest,
    ControlProducerResponse,
)
from fieldtrue.receipts import load_or_create_signing_key
from fieldtrue.runner_trust import AuthenticatedRunner, RunnerAcquisitionError

ZERO_HASH = "0" * 64
ZERO_BLOB = "0" * 40


def _git(repo: Path, *arguments: str) -> str:
    completed = subprocess.run(  # noqa: S603 - fixed Git with test-controlled arguments
        ["/usr/bin/git", *arguments],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _minimal_repository(tmp_path: Path) -> tuple[Path, AcquisitionContract]:
    repo = tmp_path / "repo"
    repo.mkdir()
    for _name, relative in authority._SOURCE_PATHS:
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"fixture:{relative}\n")
    contract_value = read_json(
        Path(__file__).parents[2] / "protocol" / "acquisition" / "iter001_contract.json"
    )
    contract_path = repo / "protocol" / "acquisition" / "iter001_contract.json"
    contract_path.parent.mkdir(parents=True, exist_ok=True)
    contract_path.write_bytes(canonical_json_pretty(contract_value))
    (repo / ".gitignore").write_text(".local/\n")
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "producer@example.invalid")
    _git(repo, "config", "user.name", "Producer Test")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "fixture authority")
    return repo, AcquisitionContract.model_validate(contract_value)


def test_producer_request_and_response_are_closed_typed_contracts(tmp_path: Path) -> None:
    request = ControlProducerRequest(
        request_id=ZERO_HASH,
        repository_root=str(tmp_path.resolve()),
        execution_commit=ZERO_BLOB,
        execution_tree="1" * 40,
        timeout_seconds=30,
    )
    assert request.operation == "generate-iter001-admission-controls"

    with pytest.raises(ValidationError, match="absolute normalized"):
        ControlProducerRequest(
            request_id=ZERO_HASH,
            repository_root="relative/repo",
            execution_commit=ZERO_BLOB,
            execution_tree="1" * 40,
            timeout_seconds=30,
        )
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ControlProducerRequest.model_validate(
            {
                **request.model_dump(mode="json"),
                "caller_supplied_receipt_sha256": ZERO_HASH,
            }
        )
    with pytest.raises(ValidationError, match="published producer response is incomplete"):
        ControlProducerResponse(
            request_id=ZERO_HASH,
            request_sha256=ZERO_HASH,
            status="published",
        )
    with pytest.raises(ValidationError, match="exposes authority fields"):
        ControlProducerResponse(
            request_id=ZERO_HASH,
            request_sha256=ZERO_HASH,
            status="rejected",
            failure_code="rejected",
            receipt_sha256=ZERO_HASH,
        )


def test_launcher_and_child_share_the_exact_platform_environment(tmp_path: Path) -> None:
    environment = launcher._producer_environment(SimpleNamespace(scratch_root=tmp_path))

    assert set(environment) == producer._EXPECTED_ENVIRONMENT_KEYS
    assert all(
        environment[name] == value for name, value in producer.CONTROL_PRODUCER_PLATFORM_ENVIRONMENT
    )


def test_child_request_reader_rejects_duplicate_noncanonical_and_oversized_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = ControlProducerRequest(
        request_id=ZERO_HASH,
        repository_root=str(tmp_path.resolve()),
        execution_commit=ZERO_BLOB,
        execution_tree="1" * 40,
        timeout_seconds=30,
    )
    canonical = canonical_json_pretty(request)
    monkeypatch.setattr(producer.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(canonical)))
    assert producer._read_request() == (request, canonical)

    duplicate = canonical.replace(
        b'"request_id":',
        b'"request_id":"' + (b"1" * 64) + b'","request_id":',
        1,
    )
    monkeypatch.setattr(producer.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(duplicate)))
    with pytest.raises(ControlAuthorityError, match="not canonical"):
        producer._read_request()

    oversized = b"x" * (producer.MAX_CONTROL_PRODUCER_REQUEST_BYTES + 1)
    monkeypatch.setattr(producer.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(oversized)))
    with pytest.raises(ControlAuthorityError, match="size is invalid"):
        producer._read_request()

    monkeypatch.setattr(producer.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b"{")))
    with pytest.raises(ControlAuthorityError, match="request is invalid"):
        producer._read_request()


def test_canonical_profile_is_rejected_before_key_access_or_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, _contract = _minimal_repository(tmp_path)
    key_reached = False

    def forbidden_key(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal key_reached
        key_reached = True
        raise AssertionError("canonical V1 reached key custody")

    monkeypatch.setattr(producer, "_read_existing_key", forbidden_key)
    commit = _git(repo, "rev-parse", "HEAD")
    tree = _git(repo, "rev-parse", "HEAD^{tree}")
    with pytest.raises(ControlAuthorityError, match="disabled pending V2"):
        producer._produce_fixture_bundle(
            repo,
            cast(AuthenticatedRunner, object()),
            expected_commit=commit,
            expected_tree=tree,
            timeout_seconds=30,
        )
    assert key_reached is False
    assert not (repo / Path(CONTROL_PRODUCER_RECEIPT_PATH).parent).exists()


def test_producer_rejects_wrong_requested_git_identity_before_output(tmp_path: Path) -> None:
    repo, _contract = _minimal_repository(tmp_path)
    tree = _git(repo, "rev-parse", "HEAD^{tree}")
    with pytest.raises(ControlAuthorityError, match="differs from the launcher request"):
        producer._produce_fixture_bundle(
            repo,
            cast(AuthenticatedRunner, object()),
            expected_commit="f" * 40,
            expected_tree=tree,
            timeout_seconds=30,
        )
    assert not (repo / Path(CONTROL_PRODUCER_RECEIPT_PATH).parent).exists()


def test_fixture_profile_cannot_select_the_canonical_trust_key(tmp_path: Path) -> None:
    _repo, contract = _minimal_repository(tmp_path)
    value = contract.model_dump(mode="json")
    value.update(
        authority_profile="test_fixture",
        control_authority_status="test_fixture",
    )
    with pytest.raises(ValidationError, match="distinct noncanonical trust key"):
        AcquisitionContract.model_validate(value)


def test_execution_contract_must_match_exact_committed_bytes(tmp_path: Path) -> None:
    repo, _contract = _minimal_repository(tmp_path)
    commit = _git(repo, "rev-parse", "HEAD")
    contract_path = repo / "protocol" / "acquisition" / "iter001_contract.json"
    contract_path.write_bytes(contract_path.read_bytes() + b"\n")

    with pytest.raises(ControlAuthorityError, match="differs from committed authority"):
        producer._load_execution_contract(repo, commit)


@pytest.mark.parametrize("mutation", ["substitute-test", "inject-module"])
def test_source_closure_rejects_snapshot_substitution_and_extra_files(
    tmp_path: Path,
    mutation: str,
) -> None:
    repo, _contract = _minimal_repository(tmp_path)
    commit = _git(repo, "rev-parse", "HEAD")
    snapshot = tmp_path / "snapshot"
    assert launcher._materialize_commit_snapshot(repo, commit, snapshot)
    if mutation == "substitute-test":
        target = snapshot / "tests" / "unit" / "test_acquisition.py"
        target.chmod(0o600)
        target.write_text("substituted control\n")
        target.chmod(0o400)
    else:
        target = snapshot / "src" / "pytest.py"
        target.write_text("substituted dependency\n")
        target.chmod(0o400)
    sources = tuple(
        authority._git_bound_source(repo, commit, name, path)
        for name, path in authority._SOURCE_PATHS
    )
    runner = cast(AuthenticatedRunner, SimpleNamespace(snapshot_root=snapshot))

    with pytest.raises(ControlAuthorityError, match="producer snapshot"):
        producer._verify_source_closure(repo, runner, commit, sources)


def test_source_closure_accepts_exact_snapshot_and_committed_import_census(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, _contract = _minimal_repository(tmp_path)
    commit = _git(repo, "rev-parse", "HEAD")
    snapshot = tmp_path / "snapshot"
    assert launcher._materialize_commit_snapshot(repo, commit, snapshot)
    sources = tuple(
        authority._git_bound_source(repo, commit, name, path)
        for name, path in authority._SOURCE_PATHS
    )
    validator = next(source for source in sources if source.name == "validator")
    closure = SimpleNamespace(
        closure_sha256="5" * 64,
        sources=(
            (
                validator.path,
                "100644",
                validator.git_blob,
                validator.sha256,
                validator.bytes,
            ),
        ),
    )

    def source_closure(*_args: Any, **kwargs: Any) -> Any:
        assert kwargs["working_source_root"] == snapshot
        assert kwargs["working_source_private_read_only"] is True
        return closure

    monkeypatch.setattr(producer, "_acquisition_source_closure", source_closure)
    runner = cast(AuthenticatedRunner, SimpleNamespace(snapshot_root=snapshot))

    assert producer._verify_source_closure(repo, runner, commit, sources) == ("5" * 64, 1)


def test_child_reconstructs_every_authenticated_runner_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "runner"
    snapshot = root / "snapshot"
    source_root = snapshot / "src"
    package_root = source_root / "fieldtrue"
    site_packages = root / "authenticated-site-packages"
    scratch = root / "runner-scratch"
    interpreter_root = root / "python-install"
    python_path = interpreter_root / "bin" / "python3.12"
    uv_path = root / "authenticated-uv" / "uv"
    for directory in (
        package_root,
        site_packages,
        scratch,
        python_path.parent,
        uv_path.parent,
    ):
        directory.mkdir(parents=True, exist_ok=True)
    python_path.write_bytes(b"python")
    uv_path.write_bytes(b"uv")
    (snapshot / "uv.lock").write_text("")

    expected_origins = {
        "fieldtrue.control_producer": "control_producer.py",
        "fieldtrue.control_authority": "control_authority.py",
        "fieldtrue.control_protocol": "control_protocol.py",
        "fieldtrue.runner_trust": "runner_trust.py",
    }
    for module_name, filename in expected_origins.items():
        path = package_root / filename
        path.write_text(f"fixture:{module_name}\n")
        module = sys.modules[module_name]
        monkeypatch.setattr(module, "__file__", str(path))

    binding = producer.runner_trust.ExecutableBinding(
        lexical_path=python_path,
        resolved_path=python_path,
        sha256="1" * 64,
        size=6,
        mode=0o500,
        owner_uid=os.getuid(),
        owner_gid=os.getgid(),
    )
    uv_binding = producer.runner_trust.PinnedUvBinding(
        executable=binding,
        version="uv fixture",
        target="fixture-target",
    )
    wheel = producer.runner_trust.LockedWheel(
        distribution="pytest",
        version="9.0.0",
        url="https://example.invalid/pytest.whl",
        sha256="2" * 64,
        size=1,
        filename="pytest.whl",
    )
    host_tool = producer.runner_trust.HostToolBinding(
        trust_root="fixture-root",
        system="fixture-system",
        machine="fixture-machine",
        release="fixture-release",
        version="fixture-version",
        tool=None,
    )
    environment = {
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PATH": producer._SAFE_PATH,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "TEMP": str(scratch),
        "TMP": str(scratch),
        "TMPDIR": str(scratch),
        "TZ": "UTC",
    }
    environment.update(producer.CONTROL_PRODUCER_PLATFORM_ENVIRONMENT)
    platform_key = (
        producer.platform.system().casefold(),
        producer.platform.machine().casefold(),
    )

    monkeypatch.setattr(
        producer.sys,
        "flags",
        SimpleNamespace(isolated=1, no_site=1, dont_write_bytecode=1, safe_path=True),
    )
    monkeypatch.setattr(producer.sys, "path", [str(source_root), str(site_packages)])
    monkeypatch.setattr(producer.sys, "base_prefix", str(interpreter_root))
    monkeypatch.setattr(producer.sys, "executable", str(python_path))
    monkeypatch.setattr(producer.os, "environ", environment)
    monkeypatch.setattr(
        producer,
        "PINNED_PYTHON_ARTIFACTS",
        {platform_key: ("fixture", "fixture.tar.gz", "https://example.invalid", "4" * 64, 1)},
    )
    monkeypatch.setattr(
        producer.runner_trust, "resolve_pinned_uv", lambda *_args, **_kw: uv_binding
    )
    monkeypatch.setattr(producer.runner_trust, "bind_executable", lambda *_args, **_kw: binding)
    monkeypatch.setattr(
        producer.runner_trust,
        "resolve_locked_wheels",
        lambda *_args, **_kw: (wheel,),
    )
    monkeypatch.setattr(
        producer.importlib.metadata,
        "distributions",
        lambda **_kwargs: (SimpleNamespace(metadata={"Name": "pytest"}, version="9.0.0"),),
    )
    monkeypatch.setattr(producer.runner_trust, "tree_digest", lambda *_args, **_kw: "3" * 64)
    monkeypatch.setattr(producer.runner_trust, "host_tool_binding", lambda: host_tool)
    monkeypatch.setattr(producer.runner_trust, "runner_is_unchanged", lambda _runner: True)

    runner = producer._reconstruct_runner()

    assert runner.root == root
    assert runner.snapshot_root == snapshot
    assert runner.python == binding
    assert runner.uv == uv_binding
    assert runner.python_artifact_sha256 == "4" * 64
    assert runner.environment_sha256 == "3" * 64
    assert runner.distribution_versions == (("pytest", "9.0.0"),)


def test_key_custody_accepts_only_single_link_mode_0600_exact_public_key(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    key_path = repo / CONTROL_PRODUCER_KEY_PATH
    key = load_or_create_signing_key(key_path)
    loaded = producer._read_existing_key(repo, key.verify_key.encode().hex())
    assert loaded.verify_key == key.verify_key

    with pytest.raises(ControlAuthorityError, match="differs from the contract"):
        producer._read_existing_key(repo, "1" * 64)

    alias = tmp_path / "key-alias"
    os.link(key_path, alias)
    with pytest.raises(ControlAuthorityError, match="boundary is untrusted"):
        producer._read_existing_key(repo, key.verify_key.encode().hex())


def test_key_custody_rejects_symlink_broad_mode_and_writable_parent(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    key_path = repo / CONTROL_PRODUCER_KEY_PATH
    key = load_or_create_signing_key(key_path)
    public_key = key.verify_key.encode().hex()

    key_path.chmod(0o640)
    with pytest.raises(ControlAuthorityError, match="boundary is untrusted"):
        producer._read_existing_key(repo, public_key)
    key_path.chmod(0o600)

    keys_directory = key_path.parent
    keys_directory.chmod(0o770)
    with pytest.raises(ControlAuthorityError, match="component is untrusted"):
        producer._read_existing_key(repo, public_key)
    keys_directory.chmod(0o755)

    key_path.unlink()
    target = tmp_path / "target-key"
    target.write_bytes(key.encode())
    target.chmod(0o600)
    key_path.symlink_to(target)
    with pytest.raises(ControlAuthorityError, match="cannot be opened"):
        producer._read_existing_key(repo, public_key)


def test_directory_boundaries_reject_missing_unsafe_and_untrusted_components(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing"
    with pytest.raises(ControlAuthorityError, match="boundary is unavailable"):
        producer._open_trusted_directory(missing)

    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    root.chmod(0o770)
    with pytest.raises(ControlAuthorityError, match="boundary is untrusted"):
        producer._open_trusted_directory(root)
    root.chmod(0o700)

    descriptor = producer._open_trusted_directory(root)
    try:
        for name in ("", ".", "..", "nested/child"):
            with pytest.raises(ControlAuthorityError, match="component is invalid"):
                producer._open_directory_at(descriptor, name)
        with pytest.raises(ControlAuthorityError, match="component is unavailable"):
            producer._open_directory_at(descriptor, "missing")
        child = root / "child"
        child.mkdir(mode=0o700)
        child.chmod(0o770)
        with pytest.raises(ControlAuthorityError, match="component is untrusted"):
            producer._open_directory_at(descriptor, "child")
    finally:
        os.close(descriptor)


def test_authority_and_launcher_have_no_private_signing_surface() -> None:
    forbidden = {
        "SigningKey",
        "_load_existing_key",
        "_read_existing_key",
        "issue_attestation",
        "load_or_create_signing_key",
    }
    assert forbidden.isdisjoint(vars(authority))
    assert forbidden.isdisjoint(vars(launcher))
    assert not hasattr(authority, "generate_admission_control_bundle")
    assert authority._normalized_control_command("node")[9] == "fieldtrue.control_observation"


def test_launcher_rejects_nonfixed_paths_before_runner_or_key_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    runner_reached = False

    def forbidden_runner(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal runner_reached
        runner_reached = True
        raise AssertionError("path substitution reached runner")

    monkeypatch.setattr(launcher, "_prepare_authenticated_runner", forbidden_runner)
    with pytest.raises(ControlAuthorityError, match="fixed private bundle path"):
        launcher.generate_admission_control_bundle(
            repo,
            repo / "alternate-output",
            repo / CONTROL_PRODUCER_KEY_PATH,
        )
    with pytest.raises(ControlAuthorityError, match="fixed fixture-signer path"):
        launcher.generate_admission_control_bundle(
            repo,
            repo / Path(CONTROL_PRODUCER_RECEIPT_PATH).parent,
            repo / ".local" / "keys" / "alternate-key",
        )
    assert runner_reached is False


def test_launcher_capture_bound_is_aggregate_across_both_streams(tmp_path: Path) -> None:
    script = (
        "import sys;"
        "sys.stdout.buffer.write(b'x'*9000);sys.stdout.buffer.flush();"
        "sys.stderr.buffer.write(b'y'*9000);sys.stderr.buffer.flush()"
    )
    with pytest.raises(ControlAuthorityError, match="capture bound"):
        launcher._run_bounded_producer(
            (sys.executable, "-I", "-c", script),
            cwd=tmp_path,
            env=os.environ.copy(),
            request=b"{}",
            timeout_seconds=5,
        )


def test_launcher_clean_head_rejects_dirty_and_invalid_git_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(launcher, "_run_git", lambda *_args, **_kwargs: " M source.py")
    with pytest.raises(ControlAuthorityError, match="clean repository"):
        launcher._clean_head(tmp_path)

    responses = iter(("", "not-an-object", "also-invalid"))
    monkeypatch.setattr(launcher, "_run_git", lambda *_args, **_kwargs: next(responses))
    with pytest.raises(ControlAuthorityError, match="invalid Git identity"):
        launcher._clean_head(tmp_path)


def test_launcher_timeout_terminates_and_reaps_process_group(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_popen = launcher.subprocess.Popen
    processes: list[subprocess.Popen[bytes]] = []

    def record_process(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        process = real_popen(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(launcher.subprocess, "Popen", record_process)
    with pytest.raises(subprocess.TimeoutExpired):
        launcher._run_bounded_producer(
            (sys.executable, "-I", "-c", "import time;time.sleep(30)"),
            cwd=tmp_path,
            env=os.environ.copy(),
            request=b"{}",
            timeout_seconds=1,
        )
    assert len(processes) == 1
    assert processes[0].poll() is not None
    assert not launcher._process_group_exists(processes[0])


def test_launcher_rejects_and_terminates_surviving_descendant(tmp_path: Path) -> None:
    descendant_pid_path = tmp_path / "descendant.pid"
    descendant_script = "import os,time;os.close(0);os.close(1);os.close(2);time.sleep(30)"
    parent_script = (
        "import pathlib,subprocess,sys;"
        f"process=subprocess.Popen([sys.executable,'-I','-c',{descendant_script!r}]);"
        "pathlib.Path(sys.argv[1]).write_text(str(process.pid))"
    )
    with pytest.raises(
        ControlAuthorityError,
        match=r"left descendant processes|process-group state cannot be verified",
    ):
        launcher._run_bounded_producer(
            (sys.executable, "-I", "-c", parent_script, str(descendant_pid_path)),
            cwd=tmp_path,
            env=os.environ.copy(),
            request=b"{}",
            timeout_seconds=5,
        )
    descendant_pid = int(descendant_pid_path.read_text(encoding="ascii"))
    deadline = time.monotonic() + 2
    while True:
        try:
            os.kill(descendant_pid, 0)
        except ProcessLookupError:
            break
        if time.monotonic() >= deadline:
            os.kill(descendant_pid, signal.SIGKILL)
            pytest.fail("producer descendant survived process-group cleanup")
        time.sleep(0.01)


@pytest.mark.parametrize(
    ("changed_field", "expected_error"),
    [
        (None, None),
        ("execution_commit", "response differs"),
        ("execution_tree", "response differs"),
        ("receipt_sha256", "receipt differs"),
        ("malformed", "response is invalid"),
        ("noncanonical", "response is not canonical"),
        ("stderr", "producer rejected"),
        ("rejected", "response differs"),
    ],
)
def test_launcher_binds_response_to_snapshot_and_durable_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    changed_field: str | None,
    expected_error: str | None,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    commit = "1" * 40
    tree = "2" * 40
    receipt_bytes = b'{"receipt":"fixture"}\n'
    output = repo / Path(CONTROL_PRODUCER_RECEIPT_PATH).parent
    runner = SimpleNamespace(
        python_path=tmp_path / "python",
        snapshot_root=tmp_path / "snapshot",
        site_packages=tmp_path / "site-packages",
        scratch_root=tmp_path / "scratch",
    )
    for directory in (runner.snapshot_root, runner.site_packages, runner.scratch_root):
        directory.mkdir()

    monkeypatch.setattr(launcher, "_clean_head", lambda _repo: (commit, tree))

    def prepare_runner(_repo: Path, _commit: str, root: Path) -> Any:
        assert root == root.resolve(strict=True)
        return runner

    monkeypatch.setattr(launcher, "_prepare_authenticated_runner", prepare_runner)
    monkeypatch.setattr(launcher.runner_trust, "runner_is_unchanged", lambda _runner: True)

    def run_child(
        _command: tuple[str, ...],
        *,
        cwd: Path,
        env: dict[str, str],
        request: bytes,
        timeout_seconds: int,
    ) -> subprocess.CompletedProcess[bytes]:
        del cwd, env, timeout_seconds
        parsed_request = ControlProducerRequest.model_validate_json(request, strict=True)
        output.mkdir(parents=True)
        (repo / CONTROL_PRODUCER_RECEIPT_PATH).write_bytes(receipt_bytes)
        values: dict[str, Any] = {
            "request_id": parsed_request.request_id,
            "request_sha256": sha256_bytes(request),
            "status": "published",
            "execution_commit": commit,
            "execution_tree": tree,
            "receipt_sha256": sha256_bytes(receipt_bytes),
            "published_path": CONTROL_PRODUCER_RECEIPT_PATH,
            "control_count": 22,
        }
        if changed_field == "execution_commit":
            values[changed_field] = "3" * 40
        elif changed_field == "execution_tree":
            values[changed_field] = "4" * 40
        elif changed_field == "receipt_sha256":
            values[changed_field] = ZERO_HASH
        if changed_field == "rejected":
            values = {
                "request_id": parsed_request.request_id,
                "request_sha256": sha256_bytes(request),
                "status": "rejected",
                "failure_code": CONTROL_PRODUCER_FAILURE_CODE,
            }
        response = ControlProducerResponse.model_validate(values)
        stdout = canonical_json_pretty(response)
        stderr = b""
        if changed_field == "malformed":
            stdout = b"{"
        elif changed_field == "noncanonical":
            stdout += b"\n"
        elif changed_field == "stderr":
            stderr = b"stable-rejection"
        return subprocess.CompletedProcess(
            args=(),
            returncode=0,
            stdout=stdout,
            stderr=stderr,
        )

    monkeypatch.setattr(launcher, "_run_bounded_producer", run_child)
    arguments = (
        repo,
        output,
        repo / CONTROL_PRODUCER_KEY_PATH,
    )
    if expected_error is None:
        assert launcher.generate_admission_control_bundle(*arguments) == (
            repo / CONTROL_PRODUCER_RECEIPT_PATH
        )
    else:
        with pytest.raises(ControlAuthorityError, match=expected_error):
            launcher.generate_admission_control_bundle(*arguments)


def test_disconnected_preregistration_commit_fails_even_when_object_resolves(
    tmp_path: Path,
) -> None:
    repo, contract = _minimal_repository(tmp_path)
    head = _git(repo, "rev-parse", "HEAD")
    tree = _git(repo, "rev-parse", "HEAD^{tree}")
    disconnected = _git(repo, "commit-tree", tree, "-m", "disconnected preregistration")
    disconnected_contract = contract.model_copy(update={"preregistration_commit": disconnected})
    with pytest.raises(ControlAuthorityError, match="not control-execution ancestry"):
        producer._verify_preregistration_ancestry(repo, disconnected_contract, head)

    connected_contract = contract.model_copy(update={"preregistration_commit": head})
    producer._verify_preregistration_ancestry(repo, connected_contract, head)


def test_preregistration_ancestry_timeout_is_normalized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, contract = _minimal_repository(tmp_path)
    head = _git(repo, "rev-parse", "HEAD")

    def timeout(*_args: Any, **_kwargs: Any) -> int:
        raise subprocess.TimeoutExpired(("git", "merge-base"), 10)

    monkeypatch.setattr(producer, "subprocess_run_git_ancestry", timeout)
    with pytest.raises(ControlAuthorityError, match="ancestry cannot be checked"):
        producer._verify_preregistration_ancestry(repo, contract, head)


def test_preregistration_bytes_must_match_frozen_ancestor(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    preregistration_path = (
        repo / "experiments" / "iter001_physical_causal_evidence_acquisition" / "HYPOTHESIS.md"
    )
    preregistration_path.parent.mkdir(parents=True)
    frozen = b"frozen preregistration\n"
    preregistration_path.write_bytes(frozen)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "prereg@example.invalid")
    _git(repo, "config", "user.name", "Prereg Test")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "freeze preregistration")
    preregistration_commit = _git(repo, "rev-parse", "HEAD")

    value = read_json(
        Path(__file__).parents[2] / "protocol" / "acquisition" / "iter001_contract.json"
    )
    value.update(
        authority_profile="test_fixture",
        control_authority_status="test_fixture",
        trust_anchor_public_key="1" * 64,
        preregistration_commit=preregistration_commit,
        preregistration_sha256=sha256_bytes(frozen),
    )
    contract = AcquisitionContract.model_validate(value)
    preregistration_path.write_text("mutated after preregistration\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "mutate preregistration")
    execution_commit = _git(repo, "rev-parse", "HEAD")

    with pytest.raises(ControlAuthorityError, match="differ from frozen authority"):
        producer._verify_preregistration_bytes(repo, contract, execution_commit)


def test_child_failure_response_exposes_only_stable_rejection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = ControlProducerRequest(
        request_id=ZERO_HASH,
        repository_root=str(tmp_path.resolve()),
        execution_commit=ZERO_BLOB,
        execution_tree="1" * 40,
        timeout_seconds=30,
    )
    raw = canonical_json_pretty(request)
    stdout = io.BytesIO()
    monkeypatch.setattr(producer.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(raw)))
    monkeypatch.setattr(producer.sys, "stdout", SimpleNamespace(buffer=stdout))
    monkeypatch.setattr(
        producer, "_reconstruct_runner", lambda: cast(AuthenticatedRunner, object())
    )
    monkeypatch.setattr(
        producer,
        "_produce_fixture_bundle",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("sensitive /private/path diagnostic")
        ),
    )

    assert producer.producer_child_main() == 1
    response = ControlProducerResponse.model_validate_json(stdout.getvalue(), strict=True)
    assert response.status == "rejected"
    assert response.failure_code == CONTROL_PRODUCER_FAILURE_CODE
    assert response.request_sha256 == sha256_bytes(raw)
    assert b"private" not in stdout.getvalue()


def test_child_runner_acquisition_failure_is_stable_bound_and_non_sensitive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = ControlProducerRequest(
        request_id=ZERO_HASH,
        repository_root=str(tmp_path.resolve()),
        execution_commit=ZERO_BLOB,
        execution_tree="1" * 40,
        timeout_seconds=30,
    )
    raw = canonical_json_pretty(request)
    stdout = io.BytesIO()
    monkeypatch.setattr(producer.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(raw)))
    monkeypatch.setattr(producer.sys, "stdout", SimpleNamespace(buffer=stdout))

    def acquisition_failure() -> AuthenticatedRunner:
        raise RunnerAcquisitionError("sensitive /private/cache/path and remote detail")

    monkeypatch.setattr(producer, "_reconstruct_runner", acquisition_failure)
    monkeypatch.setattr(
        producer,
        "_produce_fixture_bundle",
        lambda *_args, **_kwargs: pytest.fail("acquisition failure reached production"),
    )

    assert producer.producer_child_main() == 1
    response_bytes = stdout.getvalue()
    response = ControlProducerResponse.model_validate_json(response_bytes, strict=True)
    assert response_bytes == canonical_json_pretty(response)
    assert response.request_id == request.request_id
    assert response.request_sha256 == sha256_bytes(raw)
    assert response.status == "rejected"
    assert response.failure_code == CONTROL_PRODUCER_RUNNER_ACQUISITION_FAILURE_CODE
    assert b"sensitive" not in response_bytes
    assert b"private" not in response_bytes


def test_child_bundle_acquisition_failure_preserves_the_typed_response(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = ControlProducerRequest(
        request_id=ZERO_HASH,
        repository_root=str(tmp_path.resolve()),
        execution_commit=ZERO_BLOB,
        execution_tree="1" * 40,
        timeout_seconds=30,
    )
    raw = canonical_json_pretty(request)
    stdout = io.BytesIO()
    monkeypatch.setattr(producer.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(raw)))
    monkeypatch.setattr(producer.sys, "stdout", SimpleNamespace(buffer=stdout))
    monkeypatch.setattr(
        producer,
        "_reconstruct_runner",
        lambda: cast(AuthenticatedRunner, object()),
    )

    def acquisition_failure(*_args: Any, **_kwargs: Any) -> Any:
        raise RunnerAcquisitionError("sensitive /private/bundle/path and remote detail")

    monkeypatch.setattr(producer, "_produce_fixture_bundle", acquisition_failure)

    assert producer.producer_child_main() == 1
    response_bytes = stdout.getvalue()
    response = ControlProducerResponse.model_validate_json(response_bytes, strict=True)
    assert response_bytes == canonical_json_pretty(response)
    assert response.status == "rejected"
    assert response.failure_code == CONTROL_PRODUCER_RUNNER_ACQUISITION_FAILURE_CODE
    assert response.request_sha256 == sha256_bytes(raw)
    assert b"sensitive" not in response_bytes
    assert b"private" not in response_bytes


def test_launcher_reconstructs_only_exact_child_runner_acquisition_failure(
    tmp_path: Path,
) -> None:
    request = ControlProducerRequest(
        request_id=ZERO_HASH,
        repository_root=str(tmp_path.resolve()),
        execution_commit=ZERO_BLOB,
        execution_tree="1" * 40,
        timeout_seconds=30,
    )
    request_bytes = canonical_json_pretty(request)
    response = ControlProducerResponse(
        request_id=request.request_id,
        request_sha256=sha256_bytes(request_bytes),
        status="rejected",
        failure_code=CONTROL_PRODUCER_RUNNER_ACQUISITION_FAILURE_CODE,
    )
    completed = subprocess.CompletedProcess(
        args=(),
        returncode=1,
        stdout=canonical_json_pretty(response),
        stderr=b"",
    )

    with pytest.raises(
        RunnerAcquisitionError,
        match="producer runner acquisition could not be completed",
    ) as caught:
        launcher._validated_producer_response(completed, request, request_bytes)
    assert "private" not in str(caught.value)


def test_launcher_preserves_an_exact_generic_child_rejection(
    tmp_path: Path,
) -> None:
    request = ControlProducerRequest(
        request_id=ZERO_HASH,
        repository_root=str(tmp_path.resolve()),
        execution_commit=ZERO_BLOB,
        execution_tree="1" * 40,
        timeout_seconds=30,
    )
    request_bytes = canonical_json_pretty(request)
    response = ControlProducerResponse(
        request_id=request.request_id,
        request_sha256=sha256_bytes(request_bytes),
        status="rejected",
        failure_code=CONTROL_PRODUCER_FAILURE_CODE,
    )
    completed = subprocess.CompletedProcess(
        args=(),
        returncode=1,
        stdout=canonical_json_pretty(response),
        stderr=b"",
    )

    with pytest.raises(ControlAuthorityError, match="producer rejected") as caught:
        launcher._validated_producer_response(completed, request, request_bytes)
    assert not isinstance(caught.value, RunnerAcquisitionError)


@pytest.mark.parametrize(
    "fault",
    [
        "zero-status",
        "other-status",
        "stderr",
        "request-id",
        "request-sha256",
        "noncanonical",
        "unknown-code",
        "malformed",
        "published-nonzero",
    ],
)
def test_launcher_does_not_reconstruct_spoofed_child_acquisition_failure(
    tmp_path: Path,
    fault: str,
) -> None:
    request = ControlProducerRequest(
        request_id=ZERO_HASH,
        repository_root=str(tmp_path.resolve()),
        execution_commit=ZERO_BLOB,
        execution_tree="1" * 40,
        timeout_seconds=30,
    )
    request_bytes = canonical_json_pretty(request)
    values: dict[str, Any] = {
        "request_id": request.request_id,
        "request_sha256": sha256_bytes(request_bytes),
        "status": "rejected",
        "failure_code": CONTROL_PRODUCER_RUNNER_ACQUISITION_FAILURE_CODE,
    }
    returncode = 1
    stderr = b""
    if fault == "zero-status":
        returncode = 0
    elif fault == "other-status":
        returncode = 2
    elif fault == "stderr":
        stderr = b"sensitive /private/child/path"
    elif fault == "request-id":
        values["request_id"] = "1" * 64
    elif fault == "request-sha256":
        values["request_sha256"] = "2" * 64
    elif fault == "unknown-code":
        values["failure_code"] = "unknown-child-failure"
    elif fault == "published-nonzero":
        values = {
            "request_id": request.request_id,
            "request_sha256": sha256_bytes(request_bytes),
            "status": "published",
            "execution_commit": request.execution_commit,
            "execution_tree": request.execution_tree,
            "receipt_sha256": "3" * 64,
            "published_path": CONTROL_PRODUCER_RECEIPT_PATH,
            "control_count": 22,
        }
    response = ControlProducerResponse.model_validate(values)
    stdout = canonical_json_pretty(response)
    if fault == "noncanonical":
        stdout += b"\n"
    elif fault == "malformed":
        stdout = b"{"
    completed = subprocess.CompletedProcess(
        args=(),
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )

    with pytest.raises(ControlAuthorityError) as caught:
        launcher._validated_producer_response(completed, request, request_bytes)
    assert not isinstance(caught.value, RunnerAcquisitionError)
    assert "private" not in str(caught.value)


def test_child_success_response_binds_request_identity_and_receipt_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path.resolve()
    request = ControlProducerRequest(
        request_id=ZERO_HASH,
        repository_root=str(repo),
        execution_commit=ZERO_BLOB,
        execution_tree="1" * 40,
        timeout_seconds=30,
    )
    raw = canonical_json_pretty(request)
    stdout = io.BytesIO()
    monkeypatch.setattr(producer.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(raw)))
    monkeypatch.setattr(producer.sys, "stdout", SimpleNamespace(buffer=stdout))
    monkeypatch.setattr(
        producer,
        "_reconstruct_runner",
        lambda: cast(AuthenticatedRunner, object()),
    )
    monkeypatch.setattr(
        producer,
        "_produce_fixture_bundle",
        lambda *_args, **_kwargs: (
            repo / CONTROL_PRODUCER_RECEIPT_PATH,
            request.execution_commit,
            request.execution_tree,
            "6" * 64,
        ),
    )

    assert producer.producer_child_main() == 0
    response = ControlProducerResponse.model_validate_json(stdout.getvalue(), strict=True)
    assert response.status == "published"
    assert response.request_id == request.request_id
    assert response.request_sha256 == sha256_bytes(raw)
    assert response.execution_commit == request.execution_commit
    assert response.execution_tree == request.execution_tree
    assert response.receipt_sha256 == "6" * 64
    assert response.published_path == CONTROL_PRODUCER_RECEIPT_PATH
    assert response.control_count == 22


def test_child_rejects_unexpected_receipt_path_and_suppresses_write_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = ControlProducerRequest(
        request_id=ZERO_HASH,
        repository_root=str(tmp_path.resolve()),
        execution_commit=ZERO_BLOB,
        execution_tree="1" * 40,
        timeout_seconds=30,
    )
    raw = canonical_json_pretty(request)
    stdout = io.BytesIO()
    monkeypatch.setattr(producer.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(raw)))
    monkeypatch.setattr(producer.sys, "stdout", SimpleNamespace(buffer=stdout))
    monkeypatch.setattr(
        producer,
        "_reconstruct_runner",
        lambda: cast(AuthenticatedRunner, object()),
    )
    monkeypatch.setattr(
        producer,
        "_produce_fixture_bundle",
        lambda *_args, **_kwargs: (
            tmp_path / "unexpected-receipt.json",
            request.execution_commit,
            request.execution_tree,
            "6" * 64,
        ),
    )
    assert producer.producer_child_main() == 1
    response = ControlProducerResponse.model_validate_json(stdout.getvalue(), strict=True)
    assert response.status == "rejected"

    class BrokenOutput:
        def write(self, _data: bytes) -> int:
            raise OSError("closed producer response pipe")

        def flush(self) -> None:
            raise AssertionError("flush must not follow a failed write")

    monkeypatch.setattr(producer.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(raw)))
    monkeypatch.setattr(producer.sys, "stdout", SimpleNamespace(buffer=BrokenOutput()))
    assert producer.producer_child_main() == 3


def test_child_malformed_request_exits_without_diagnostics(monkeypatch: pytest.MonkeyPatch) -> None:
    stdout = io.BytesIO()
    monkeypatch.setattr(producer.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b"{")))
    monkeypatch.setattr(producer.sys, "stdout", SimpleNamespace(buffer=stdout))

    assert producer.producer_child_main() == 2
    assert stdout.getvalue() == b""
