from __future__ import annotations

import re
import shlex
import tomllib
from pathlib import Path

_REPO_ROOT = Path(__file__).parents[2]
_BUILD_COMMAND = (
    "uv build --build-constraints requirements/build-constraints.txt --require-hashes "
    "--python 3.12.13 --managed-python"
)
_BUILD_CLOSURE = {
    "hatchling": (
        "1.31.0",
        "aac80bec8b6fe35e8480f1c335be8910fa210a0e6f735a139be205dadcacb544",
    ),
    "packaging": (
        "26.2",
        "5fc45236b9446107ff2415ce77c807cee2862cb6fac22b8a73826d0693b0980e",
    ),
    "pathspec": (
        "1.1.1",
        "a00ce642f577bf7f473932318056212bc4f8bfdf53128c78bbd5af0b9b20b189",
    ),
    "pluggy": (
        "1.6.0",
        "e920276dd6813095e9377c0bc5566d94c932c33b27a3e3945d8389c374dd4746",
    ),
    "trove-classifiers": (
        "2026.6.1.19",
        "ab4c4ec93cc4a4e7815fa759906e05e6bb3f2fbd92ea0f897288c6a43efd15b3",
    ),
}


def test_build_backend_and_complete_closure_are_exactly_pinned() -> None:
    project = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["build-system"]["requires"] == ["hatchling==1.31.0"]
    assert project["tool"]["uv"]["link-mode"] == "copy"
    assert (
        "/requirements/build-constraints.txt"
        in (project["tool"]["hatch"]["build"]["targets"]["sdist"]["include"])
    )

    constraints = (_REPO_ROOT / "requirements" / "build-constraints.txt").read_text(
        encoding="utf-8"
    )
    observed = {
        name: (version, digest)
        for name, version, digest in re.findall(
            r"^([a-z0-9-]+)==([^ \\n]+) \\\n"
            r"    --hash=sha256:([0-9a-f]{64})$",
            constraints,
            flags=re.MULTILINE,
        )
    }
    assert observed == _BUILD_CLOSURE


def test_package_workflow_cannot_fall_back_to_a_floating_build_backend() -> None:
    workflow = (_REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "uv python install 3.11 3.12.13 3.14" in workflow
    assert "uv sync --group release --frozen --python 3.12.13 --managed-python" in workflow
    sync_steps = tuple(
        line.strip() for line in workflow.splitlines() if line.strip().startswith("- run: uv sync ")
    )
    assert len(sync_steps) == 6
    assert all("--link-mode" not in step for step in sync_steps)
    assert workflow.count(_BUILD_COMMAND) == 2
    assert "uv run python -c 'import pyarrow; print(pyarrow.__version__)'" in workflow


def test_uv_workflows_cannot_override_project_copy_mode() -> None:
    workflow_paths = sorted((_REPO_ROOT / ".github" / "workflows").glob("*.yml"))
    uv_workflows = {
        path.name: path.read_text(encoding="utf-8")
        for path in workflow_paths
        if "astral-sh/setup-uv@" in path.read_text(encoding="utf-8")
    }
    assert set(uv_workflows) == {"ci.yml", "memory-integrity.yml"}
    for workflow in uv_workflows.values():
        assert re.search(r"^\s*UV_LINK_MODE:", workflow, flags=re.MULTILINE) is None
        sync_steps = tuple(
            line.strip()
            for line in workflow.splitlines()
            if line.strip().startswith("- run: uv sync ")
        )
        assert sync_steps
        assert all("--link-mode" not in step for step in sync_steps)


def test_documented_environment_recovery_reinstalls_under_copy_mode() -> None:
    for relative in ("AGENTS.md", "README.md", "CONTRIBUTING.md"):
        document = (_REPO_ROOT / relative).read_text(encoding="utf-8")
        assert "uv sync --link-mode copy --reinstall" in document


def test_coverage_floor_cannot_round_a_sub_90_result_to_pass() -> None:
    project = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    report = project["tool"]["coverage"]["report"]

    assert report["precision"] == 2
    assert report["fail_under"] == 90.01
    assert round(89.999, report["precision"]) < report["fail_under"]


def test_pytest_defaults_execute_xfails_without_selecting_a_subset() -> None:
    project = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    addopts = shlex.split(project["tool"]["pytest"]["ini_options"]["addopts"])

    assert addopts == ["-q", "--strict-markers", "--strict-config", "--runxfail"]
