"""The falsifiability rule, enforced by the suite that already runs in CI.

`scripts/ci/verify_guard_coverage.py` exists because the vacuous-guard rule recorded in
`CONTINUITY.md` was written as prose and never mechanized, and then recurred: commit `51d1885`
shipped an authority module in which 42 of 71 guards had no test that could make them fire.

The guard is invoked from here rather than from `ci.yml` for the same reason
`tests/unit/test_conventions.py` gives: `CONTINUITY.md` reserves workflow changes for a separately
audited policy-bootstrap ceremony, and a candidate branch that edits its own CI definition is
exactly what that reservation prevents.

The rule is verified against deliberately broken subjects below, because a rule about falsifiable
guards that was itself only checked against a passing tree would be the defect it names.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import textwrap
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parents[2]
GUARD = REPO_ROOT / "scripts" / "ci" / "verify_guard_coverage.py"


def _load_guard() -> ModuleType:
    """Import the committed guard so its rules can be exercised directly."""
    spec = importlib.util.spec_from_file_location("guard_coverage_guard", GUARD)
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
        timeout=1800,
    )


def test_every_authority_guard_is_falsifiable() -> None:
    """No registered authority module may ship a guard no broken subject reaches."""
    result = _run_guard()
    assert result.returncode == 0, f"guard-coverage failed:\n{result.stdout}\n{result.stderr}"
    assert "GUARD_COVERAGE_VERIFIED" in result.stdout


def test_guard_reports_every_rule_it_ran() -> None:
    """A guard that silently skips a rule cannot be audited from its own output."""
    result = _run_guard()
    assert "authority guards are falsifiable" in result.stdout


def test_rule_fails_when_a_guard_is_never_exercised() -> None:
    """Positive control: the rule must actually be able to fail.

    This is the exact defect the rule names. A falsifiability rule checked only against a module
    whose guards are all covered would itself be a guard that cannot fail.
    """
    module = _load_guard()
    source = textwrap.dedent(
        """
        def check(value: int) -> int:
            if value < 0:
                raise ValueError("negative")
            return value
        """
    )
    (guard_line,) = module.guard_line_spans(source)

    assert module.unexercised_guards(source, {guard_line}) == [guard_line]
    assert module.unexercised_guards(source, set()) == []


def test_rule_detects_a_guard_whose_raise_spans_several_lines() -> None:
    """A multi-line `raise` is unexercised if any of its lines is unexecuted."""
    module = _load_guard()
    source = textwrap.dedent(
        """
        def check(value: int) -> int:
            if value < 0:
                raise ValueError(
                    "negative value is not permitted here",
                )
            return value
        """
    )
    spans = module.guard_line_spans(source)
    assert len(spans) == 1
    first_line, span = next(iter(spans.items()))
    assert len(span) > 1
    for line in span:
        assert module.unexercised_guards(source, {line}) == [first_line]


def test_rule_refuses_a_module_that_declares_no_guard() -> None:
    """A registered module with no guard would make the rule pass vacuously."""
    module = _load_guard()
    assert module.guard_line_spans("def check(value: int) -> int:\n    return value\n") == {}


def test_registered_modules_and_suites_exist() -> None:
    """A renamed or deleted registration would make the rule pass vacuously."""
    module = _load_guard()
    assert module.GUARDED_MODULES, "no authority module is registered"
    for guarded, suites in module.GUARDED_MODULES.items():
        assert (REPO_ROOT / guarded).is_file(), f"registered module missing: {guarded}"
        assert suites, f"registered module has no adversarial suite: {guarded}"
        for suite in suites:
            assert (REPO_ROOT / suite).is_file(), f"registered suite missing: {suite}"
