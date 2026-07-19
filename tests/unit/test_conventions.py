"""The repository's own conventions, enforced by the suite that already runs in CI.

`scripts/ci/verify_conventions.py` exists because three conventions were broken on 2026-07-18 by an
agent that had read the history and applied a tool default instead. Those conventions were enforced
only by reading the log, which is not enforcement.

The guard is invoked from here rather than from `ci.yml` because `CONTINUITY.md` reserves
workflow changes for a separately audited policy-bootstrap ceremony, and a candidate branch that
edits its own CI definition is exactly what that reservation prevents. Running it as a test
achieves the same enforcement without touching the workflow.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GUARD = REPO_ROOT / "scripts" / "ci" / "verify_conventions.py"


def _load_guard() -> ModuleType:
    """Import the committed guard so its rules can be exercised directly."""
    spec = importlib.util.spec_from_file_location("conventions_guard", GUARD)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_guard() -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed interpreter and committed script path
        [sys.executable, str(GUARD)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_repository_conventions_hold() -> None:
    """The committed tree must satisfy every rule the guard enforces."""
    result = _run_guard()
    assert result.returncode == 0, f"convention guard failed:\n{result.stdout}\n{result.stderr}"
    assert "CONVENTIONS_VERIFIED" in result.stdout


def test_guard_reports_every_rule_it_ran() -> None:
    """A guard that silently skips a rule cannot be audited from its own output."""
    result = _run_guard()
    for rule in (
        "guards have subjects",
        "no commit trailers",
        "results linked from README",
        "freezes linked from README",
        "no superseded claims",
    ):
        assert rule in result.stdout, f"guard did not report rule: {rule}"


def test_guard_fails_when_a_result_is_unlinked(tmp_path: Path) -> None:
    """Positive control: the link rule must actually be able to fail.

    A guard verified only against a passing tree is indistinguishable from a guard that returns
    success unconditionally. This is the defect that let three inert components ship in one day, and
    it is checked here rather than assumed.
    """
    module = _load_guard()

    fake_root = tmp_path / "repo"
    (fake_root / "experiments" / "iterX").mkdir(parents=True)
    (fake_root / "README.md").write_text("a README that links nothing\n", encoding="utf-8")
    (fake_root / "experiments" / "iterX" / "RESULT_ORPHAN.md").write_text(
        "orphan\n", encoding="utf-8"
    )

    original = module.REPO_ROOT
    module.REPO_ROOT = fake_root
    try:
        problems = module.check_results_are_linked()
    finally:
        module.REPO_ROOT = original

    assert problems, "the link rule passed on a tree with an unlinked result"
    assert "RESULT_ORPHAN.md" in problems[0]


def test_guard_fails_when_a_superseded_claim_reappears(tmp_path: Path) -> None:
    """Positive control: the forbidden-phrase rule must actually be able to fail."""
    module = _load_guard()

    fake_root = tmp_path / "repo2"
    fake_root.mkdir(parents=True)
    (fake_root / "README.md").write_text("no scientific result exists\n", encoding="utf-8")

    original = module.REPO_ROOT
    original_phrases = module.FORBIDDEN_PHRASES
    module.REPO_ROOT = fake_root
    module.FORBIDDEN_PHRASES = {"README.md": ("no scientific result exists",)}
    try:
        problems = module.check_forbidden_phrases()
    finally:
        module.REPO_ROOT = original
        module.FORBIDDEN_PHRASES = original_phrases

    assert problems, "the forbidden-phrase rule passed on a tree containing a superseded claim"


@pytest.mark.parametrize(
    ("surface", "phrase"),
    [
        ("README.md", "16 incidents"),
        ("README.md", "Classical active fault diagnosis is sufficient for this laboratory."),
        ("README.md", "The one result that survived."),
        ("README.md", "Inbar makes the failure modes structurally impossible"),
        ("CONTINUITY.md", "Treat this as settled for this\nlaboratory"),
        (
            "CHANGELOG.md",
            "Established that the classical set-based rule ties the information-gain selector.",
        ),
        (
            "docs/MATHEMATICS.md",
            "denominator_floor`, whose current default is `1e-9` cost units",
        ),
        ("docs/ROADMAP.md", "The active-test milestone is closed as a null"),
        (
            "docs/ROADMAP.md",
            "Existing benchmarks score whether an agent sought information, not",
        ),
        (
            "src/fieldtrue/active_selection.py",
            "This module exists under Amendment 006, ratified by owner-approval receipt",
        ),
        (
            "src/fieldtrue/graded_laboratory.py",
            "This module exists under Amendment 006, ratified by owner-approval receipt",
        ),
    ],
)
def test_evidence_correction_tripwires_can_each_fail(
    tmp_path: Path, surface: str, phrase: str
) -> None:
    """Every newly corrected narrative has a known-bad recurrence fixture."""
    module = _load_guard()

    fake_root = tmp_path / "repo"
    path = fake_root / surface
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{phrase}\n", encoding="utf-8")

    original = module.REPO_ROOT
    original_phrases = module.FORBIDDEN_PHRASES
    module.REPO_ROOT = fake_root
    module.FORBIDDEN_PHRASES = {surface: (phrase,)}
    try:
        problems = module.check_forbidden_phrases()
    finally:
        module.REPO_ROOT = original
        module.FORBIDDEN_PHRASES = original_phrases

    assert problems == [f"{surface} contains a superseded claim: {phrase!r}"]


def test_grandfathered_trailer_set_is_closed() -> None:
    """The grandfathered set records published mistakes and may never grow.

    It exists because rewriting published history to hide a convention error is worse than the
    error. If a future change needs to add to it, that change is adding a new violation rather than
    recording an old one, and the guard should have stopped it.
    """
    module = _load_guard()

    assert len(module.GRANDFATHERED_TRAILER_COMMITS) == 9, (
        "the grandfathered trailer set changed; it records nine published commits from "
        "2026-07-18 and may shrink but never grow"
    )


@pytest.mark.parametrize(
    "surface",
    ["README.md", "CONTINUITY.md", "AGENTS.md", "CHANGELOG.md"],
)
def test_required_surfaces_exist_and_are_non_empty(surface: str) -> None:
    """A missing surface would make several rules pass vacuously."""
    path = REPO_ROOT / surface
    assert path.is_file(), f"required surface missing: {surface}"
    assert path.read_text(encoding="utf-8").strip(), f"required surface is empty: {surface}"
