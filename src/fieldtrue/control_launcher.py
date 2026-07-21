"""Minimal ambient launcher for the authenticated control producer."""

from __future__ import annotations

import argparse
import os
import selectors
import signal
import stat
import subprocess
import tempfile
import time
from contextlib import suppress
from pathlib import Path, PurePosixPath
from typing import NoReturn

import fieldtrue.runner_trust as runner_trust
from fieldtrue.canonical import canonical_json_pretty, sha256_bytes
from fieldtrue.control_protocol import (
    CONTROL_PRODUCER_KEY_PATH,
    CONTROL_PRODUCER_PLATFORM_ENVIRONMENT,
    CONTROL_PRODUCER_RECEIPT_PATH,
    CONTROL_PRODUCER_SNAPSHOT_PATHS,
    MAX_CONTROL_PRODUCER_RESPONSE_BYTES,
    ControlAuthorityError,
    ControlProducerRequest,
    ControlProducerResponse,
)
from fieldtrue.git_trust import GitTrustError, git_environment, trusted_repository_git
from fieldtrue.runner_trust import (
    MAX_RUNNER_FILE_BYTES,
    MAX_RUNNER_TREE_BYTES,
    MAX_RUNNER_TREE_ENTRIES,
    AuthenticatedRunner,
    RunnerAcquisitionError,
    RunnerTrustError,
)

_RUNNER_ROOT_DISTRIBUTIONS = frozenset({"certifi", "networkx", "pydantic", "pynacl", "pytest"})
_RUNNER_SNAPSHOT_PATHS = CONTROL_PRODUCER_SNAPSHOT_PATHS
_PRODUCER_CONTROL_COUNT = 22
_PRODUCER_STARTUP_GRACE_SECONDS = 120
_PROCESS_TERMINATION_GRACE_SECONDS = 0.25
_PROCESS_GROUP_POLL_SECONDS = 0.01
_CAPTURE_READ_BYTES = 16 * 1024
_MAX_AGGREGATE_PRODUCER_CAPTURE_BYTES = MAX_CONTROL_PRODUCER_RESPONSE_BYTES
_SAFE_PATH = "/usr/bin:/bin"


def _run_git(repo: Path, *arguments: str, text: bool = True) -> str | bytes:
    try:
        git = trusted_repository_git(repo)
        completed = subprocess.run(  # noqa: S603 - fixed trusted Git and internal arguments
            (git, *arguments),
            cwd=repo,
            check=True,
            capture_output=True,
            text=text,
            env=git_environment(),
            timeout=10,
        )
    except (GitTrustError, OSError, subprocess.SubprocessError) as error:
        raise ControlAuthorityError("control launcher Git verification failed") from error
    output: str | bytes = completed.stdout
    return output.strip() if text else output


def _clean_head(repo: Path) -> tuple[str, str]:
    status = _run_git(repo, "status", "--porcelain=v1", "--untracked-files=all")
    if status:
        raise ControlAuthorityError("control launcher requires a clean repository")
    commit = str(_run_git(repo, "rev-parse", "--verify", "HEAD^{commit}"))
    tree = str(_run_git(repo, "rev-parse", f"{commit}^{{tree}}"))
    if len(commit) not in (40, 64) or len(tree) not in (40, 64):
        raise ControlAuthorityError("control launcher received an invalid Git identity")
    return commit, tree


def _materialize_commit_snapshot(repo: Path, commit: str, destination: Path) -> bool:
    try:
        raw = _run_git(
            repo,
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            commit,
            "--",
            *_RUNNER_SNAPSHOT_PATHS,
            text=False,
        )
    except ControlAuthorityError:
        return False
    if not isinstance(raw, bytes):
        return False
    records = raw.split(b"\0")
    if records[-1:] != [b""] or len(records) > MAX_RUNNER_TREE_ENTRIES:
        return False
    observed: set[str] = set()
    total_bytes = 0
    try:
        destination.mkdir(mode=0o700)
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
                or relative in observed
                or not any(
                    relative == prefix or relative.startswith(f"{prefix}/")
                    for prefix in _RUNNER_SNAPSHOT_PATHS
                )
            ):
                return False
            payload = _run_git(repo, "cat-file", "blob", object_id, text=False)
            if not isinstance(payload, bytes) or len(payload) > MAX_RUNNER_FILE_BYTES:
                return False
            total_bytes += len(payload)
            if total_bytes > MAX_RUNNER_TREE_BYTES:
                return False
            target = destination.joinpath(*pure.parts)
            parent = destination
            for component in pure.parts[:-1]:
                parent /= component
                with suppress(FileExistsError):
                    parent.mkdir(mode=0o700)
                metadata = parent.lstat()
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o700
                ):
                    return False
            descriptor = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                0o500 if mode == "100755" else 0o400,
            )
            try:
                view = memoryview(payload)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        return False
                    view = view[written:]
            finally:
                os.close(descriptor)
            observed.add(relative)
    except (OSError, UnicodeDecodeError, ValueError):
        return False
    required = {
        "pyproject.toml",
        "uv.lock",
        "protocol/acquisition/iter001_contract.json",
        "src/fieldtrue/control_launcher.py",
        "src/fieldtrue/control_producer.py",
        "tests/unit/test_acquisition.py",
    }
    return required.issubset(observed)


def _prepare_authenticated_runner(repo: Path, commit: str, root: Path) -> AuthenticatedRunner:
    snapshot_root = root / "snapshot"
    if not _materialize_commit_snapshot(repo, commit, snapshot_root):
        raise ControlAuthorityError("committed producer snapshot cannot be materialized")
    try:
        return runner_trust.prepare_authenticated_runner(
            root,
            snapshot_root,
            root_distributions=_RUNNER_ROOT_DISTRIBUTIONS,
            required_imports=("nacl", "pytest"),
            artifact_cache_root=root / "artifact-cache",
        )
    except RunnerTrustError as error:
        raise ControlAuthorityError(str(error)) from error


def _producer_environment(runner: AuthenticatedRunner) -> dict[str, str]:
    environment = {
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PATH": _SAFE_PATH,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "TEMP": str(runner.scratch_root),
        "TMP": str(runner.scratch_root),
        "TMPDIR": str(runner.scratch_root),
        "TZ": "UTC",
    }
    environment.update(CONTROL_PRODUCER_PLATFORM_ENVIRONMENT)
    return environment


def _signal_process_group(process: subprocess.Popen[bytes], number: signal.Signals) -> None:
    try:
        os.killpg(process.pid, number)
    except ProcessLookupError:
        return
    except OSError:
        if process.poll() is None:
            with suppress(ProcessLookupError):
                process.send_signal(number)


def _process_group_exists(process: subprocess.Popen[bytes]) -> bool:
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return False
    except OSError as error:
        raise ControlAuthorityError("producer process-group state cannot be verified") from error
    return True


def _wait_for_process_group_exit(
    process: subprocess.Popen[bytes], *, timeout_seconds: float
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while _process_group_exists(process):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(_PROCESS_GROUP_POLL_SECONDS, remaining))
    return True


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    _signal_process_group(process, signal.SIGTERM)
    try:
        process.wait(timeout=_PROCESS_TERMINATION_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        _signal_process_group(process, signal.SIGKILL)
        try:
            process.wait(timeout=_PROCESS_TERMINATION_GRACE_SECONDS)
        except subprocess.TimeoutExpired as error:
            raise ControlAuthorityError("producer process could not be reaped") from error
    if _process_group_exists(process):
        _signal_process_group(process, signal.SIGKILL)
        if not _wait_for_process_group_exit(
            process, timeout_seconds=_PROCESS_TERMINATION_GRACE_SECONDS
        ):
            raise ControlAuthorityError("producer descendants could not be terminated")


def _run_bounded_producer(
    command: tuple[str, ...],
    *,
    cwd: Path,
    env: dict[str, str],
    request: bytes,
    timeout_seconds: int,
) -> subprocess.CompletedProcess[bytes]:
    process = subprocess.Popen(  # noqa: S603 - exact authenticated interpreter and source
        command,
        cwd=cwd,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
        start_new_session=True,
    )
    stdin = process.stdin
    stdout = process.stdout
    stderr = process.stderr
    if stdin is None or stdout is None or stderr is None:
        _terminate_process(process)
        raise ControlAuthorityError("producer pipes were not created")
    try:
        stdin.write(request)
        stdin.flush()
    except (BrokenPipeError, OSError):
        pass
    finally:
        stdin.close()

    captures = {stdout.fileno(): bytearray(), stderr.fileno(): bytearray()}
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + timeout_seconds
    try:
        for pipe in (stdout, stderr):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout_seconds)
            events = selector.select(remaining)
            if not events:
                raise subprocess.TimeoutExpired(command, timeout_seconds)
            for key, _mask in events:
                capture = captures[key.fd]
                aggregate_size = sum(len(value) for value in captures.values())
                chunk = os.read(
                    key.fd,
                    min(
                        _CAPTURE_READ_BYTES,
                        MAX_CONTROL_PRODUCER_RESPONSE_BYTES - len(capture) + 1,
                        _MAX_AGGREGATE_PRODUCER_CAPTURE_BYTES - aggregate_size + 1,
                    ),
                )
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                capture.extend(chunk)
                if (
                    len(capture) > MAX_CONTROL_PRODUCER_RESPONSE_BYTES
                    or sum(len(value) for value in captures.values())
                    > _MAX_AGGREGATE_PRODUCER_CAPTURE_BYTES
                ):
                    raise ControlAuthorityError("producer output exceeded the capture bound")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(command, timeout_seconds)
        returncode = process.wait(timeout=remaining)
        if _process_group_exists(process):
            _terminate_process(process)
            raise ControlAuthorityError("producer left descendant processes")
        return subprocess.CompletedProcess(
            command,
            returncode,
            bytes(captures[stdout.fileno()]),
            bytes(captures[stderr.fileno()]),
        )
    except BaseException:
        _terminate_process(process)
        raise
    finally:
        selector.close()
        stdout.close()
        stderr.close()


def generate_admission_control_bundle(
    repo_root: Path,
    output_directory: Path,
    signing_key_path: Path,
    *,
    timeout_seconds: int = 600,
) -> Path:
    """Launch the committed producer without importing or receiving signing authority."""

    repo = repo_root.resolve(strict=True)
    expected_output = repo / Path(CONTROL_PRODUCER_RECEIPT_PATH).parent
    expected_key = repo / CONTROL_PRODUCER_KEY_PATH
    if output_directory.absolute() != expected_output.absolute():
        raise ControlAuthorityError("producer output must use the fixed private bundle path")
    if signing_key_path.absolute() != expected_key.absolute():
        raise ControlAuthorityError("producer key must use the fixed fixture-signer path")
    if timeout_seconds <= 0 or timeout_seconds > 3600:
        raise ControlAuthorityError("producer timeout is outside the fixed bound")
    if output_directory.exists() or output_directory.is_symlink():
        raise FileExistsError(output_directory)

    commit, tree = _clean_head(repo)
    request = ControlProducerRequest(
        request_id=sha256_bytes(os.urandom(32)),
        repository_root=str(repo),
        execution_commit=commit,
        execution_tree=tree,
        timeout_seconds=timeout_seconds,
    )
    request_bytes = canonical_json_pretty(request)
    runner_temporary = tempfile.TemporaryDirectory(prefix="fieldtrue-control-producer-")
    try:
        runner_root = Path(runner_temporary.name).resolve(strict=True)
        runner = _prepare_authenticated_runner(repo, commit, runner_root)
        if not runner_trust.runner_is_unchanged(runner):
            raise ControlAuthorityError("authenticated producer runner changed before launch")
        bootstrap = (
            "import sys;sys.path[:0]=sys.argv[1:3];"
            "from fieldtrue.control_producer import producer_child_main;"
            "raise SystemExit(producer_child_main())"
        )
        command = (
            str(runner.python_path),
            "-I",
            "-B",
            "-S",
            "-c",
            bootstrap,
            str(runner.snapshot_root / "src"),
            str(runner.site_packages),
        )
        total_timeout = timeout_seconds * _PRODUCER_CONTROL_COUNT + _PRODUCER_STARTUP_GRACE_SECONDS
        completed = _run_bounded_producer(
            command,
            cwd=runner.snapshot_root,
            env=_producer_environment(runner),
            request=request_bytes,
            timeout_seconds=total_timeout,
        )
        if completed.returncode != 0 or completed.stderr:
            raise ControlAuthorityError("authenticated producer rejected the request")
        try:
            response = ControlProducerResponse.model_validate_json(completed.stdout, strict=True)
        except ValueError as error:
            raise ControlAuthorityError("authenticated producer response is invalid") from error
        if canonical_json_pretty(response) != completed.stdout:
            raise ControlAuthorityError("authenticated producer response is not canonical")
        if (
            response.request_id != request.request_id
            or response.request_sha256 != sha256_bytes(request_bytes)
            or response.status != "published"
            or response.execution_commit != commit
            or response.execution_tree != tree
        ):
            raise ControlAuthorityError("authenticated producer response differs from the request")
        if _clean_head(repo) != (commit, tree):
            raise ControlAuthorityError("repository identity changed during producer execution")
        receipt_path = repo / CONTROL_PRODUCER_RECEIPT_PATH
        receipt_bytes = runner_trust.stable_regular_bytes(
            receipt_path, maximum_bytes=MAX_RUNNER_FILE_BYTES
        )
        if receipt_bytes is None or sha256_bytes(receipt_bytes) != response.receipt_sha256:
            raise ControlAuthorityError(
                "published producer receipt differs from the child response"
            )
        return receipt_path
    finally:
        runner_temporary.cleanup()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Launch the authenticated admission-control producer"
    )
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--timeout-seconds", type=int, default=600)
    return parser


def _die(message: str) -> NoReturn:
    raise SystemExit(message)


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    repo = arguments.repo.resolve()
    try:
        receipt = generate_admission_control_bundle(
            repo,
            repo / Path(CONTROL_PRODUCER_RECEIPT_PATH).parent,
            repo / CONTROL_PRODUCER_KEY_PATH,
            timeout_seconds=arguments.timeout_seconds,
        )
    except RunnerAcquisitionError as error:
        _die(f"admission-control runner acquisition failed: {error}")
    except (ControlAuthorityError, FileExistsError, OSError, subprocess.SubprocessError) as error:
        _die(f"admission-control producer failed: {error}")
    print(receipt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
