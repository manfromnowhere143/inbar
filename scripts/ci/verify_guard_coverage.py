"""Every guard in an authority module must be exercised by a deliberately broken subject.

`CONTINUITY.md` records the vacuous-guard defect of 2026-07-18: three components shipped, each
described as doing something, each doing nothing, and each having passed controls that could not
fail on an inert component. The correction recorded there is not vigilance but mechanism.

That correction was written as a standing rule and never mechanized, so it recurred. Commit
`51d1885` added an authority module in which 42 of 71 guards had no test that could make them
fire, including guards whose results the assurance report asserts as verified. A control verified
only against a passing subject is indistinguishable from `return True`.

A guard here is a `raise` statement inside a registered authority module. The rule is that every
one must be executed by that module's registered adversarial suite. A guard no broken subject can
reach is either dead code or an untested control, and this script refuses both.

Registration is a one-way ratchet: once a module is listed, a new guard cannot be added to it
without a test that makes the guard fire.

Run:

    uv run python scripts/ci/verify_guard_coverage.py

Exits non-zero naming every unexercised guard.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Authority modules whose every guard must be falsifiable, mapped to the adversarial suites that
# must falsify them. Listing a module is a commitment, not a description: guards added to it later
# fail this check until a broken subject reaches them.
GUARDED_MODULES: dict[str, tuple[str, ...]] = {
    "src/fieldtrue/shortcut_v2_ontology.py": ("tests/unit/test_shortcut_v2_ontology.py",),
}


def guard_line_spans(source: str) -> dict[int, tuple[int, ...]]:
    """Map each guard's first line to every line the `raise` statement occupies."""
    tree = ast.parse(source)
    spans: dict[int, tuple[int, ...]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Raise):
            end = node.end_lineno or node.lineno
            spans[node.lineno] = tuple(range(node.lineno, end + 1))
    return spans


def unexercised_guards(source: str, missing_lines: set[int]) -> list[int]:
    """Return the first line of every guard that no test executed.

    Pure, so this rule can itself be verified against a deliberately broken subject rather than
    trusted. That is the rule it enforces, applied to itself.
    """
    spans = guard_line_spans(source)
    return sorted(line for line, span in spans.items() if missing_lines.intersection(span))


def _measure_missing_lines(module: str, tests: tuple[str, ...]) -> set[int]:
    """Run the registered suites under a private coverage database and report missing lines."""
    with tempfile.TemporaryDirectory() as work:
        report = Path(work) / "coverage.json"
        env = dict(os.environ)
        env["COVERAGE_FILE"] = str(Path(work) / "coverage.data")
        run = subprocess.run(  # noqa: S603 - fixed interpreter and registered suite paths
            [
                sys.executable,
                "-m",
                "coverage",
                "run",
                "--branch",
                "--source=fieldtrue",
                "-m",
                "pytest",
                *tests,
                "-p",
                "no:cacheprovider",
            ],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=1800,
        )
        if run.returncode != 0:
            raise RuntimeError(
                f"registered adversarial suite failed for {module}:\n{run.stdout}\n{run.stderr}"
            )
        report_run = subprocess.run(  # noqa: S603 - fixed interpreter and generated report path
            [
                sys.executable,
                "-m",
                "coverage",
                "json",
                f"--include=*{Path(module).name}",
                "--fail-under=0",
                "-o",
                str(report),
                "-q",
            ],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if not report.is_file():
            raise RuntimeError(
                f"coverage produced no report for {module}:\n"
                f"{report_run.stdout}\n{report_run.stderr}"
            )
        payload = json.loads(report.read_text(encoding="utf-8"))

    for recorded, data in payload.get("files", {}).items():
        if Path(recorded).name == Path(module).name:
            return set(data.get("missing_lines", ()))
    raise RuntimeError(f"coverage reported no record for {module}")


def check_authority_guards_are_falsifiable() -> list[str]:
    """Every guard in a registered authority module must fire for some broken subject."""
    problems: list[str] = []
    for module, tests in sorted(GUARDED_MODULES.items()):
        path = REPO_ROOT / module
        if not path.is_file():
            problems.append(f"registered authority module is absent: {module}")
            continue
        missing_suite = [test for test in tests if not (REPO_ROOT / test).is_file()]
        if missing_suite:
            problems.append(f"{module}: registered adversarial suite absent: {missing_suite}")
            continue
        source = path.read_text(encoding="utf-8")
        spans = guard_line_spans(source)
        if not spans:
            problems.append(f"{module}: declares no guard, so this rule would pass vacuously")
            continue
        lines = source.splitlines()
        for line in unexercised_guards(source, _measure_missing_lines(module, tests)):
            statement = lines[line - 1].strip()
            problems.append(f"{module}:{line}: no broken subject reaches this guard -- {statement}")
    return problems


RULES = (("authority guards are falsifiable", check_authority_guards_are_falsifiable),)


def main() -> int:
    failures = 0
    for name, rule in RULES:
        problems = rule()
        if problems:
            failures += len(problems)
            print(f"FAIL  {name}")
            for problem in problems:
                print(f"        {problem}")
        else:
            print(f"ok    {name}")
    if failures:
        print(f"\n{failures} unexercised authority guard(s)")
        return 1
    print("\nGUARD_COVERAGE_VERIFIED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
