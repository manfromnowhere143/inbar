"""Machine-enforced repository conventions.

Every rule here was previously enforced only by reading the history, and every rule here was broken
on 2026-07-18 by an agent that had read the history and applied a tool default instead. A convention
that depends on an author's attention is not a convention; it is a hope. This script converts the
ones that were broken into checks that fail closed.

The rules are deliberately narrow. Each corresponds to an observed, dated defect, and each carries
the reason it exists so a future reader can judge whether it still earns its place rather than
inheriting it as ceremony. A rule that no longer corresponds to a real failure should be deleted,
not kept for symmetry.

Run:

    uv run python scripts/ci/verify_conventions.py

Exits non-zero on the first violated rule with the offending artifact named.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# The repository pins a fixed Git path rather than resolving it from PATH, so a hostile PATH entry
# cannot substitute an executable. This guard follows the same rule.
TRUSTED_GIT_PATH = Path("/usr/bin/git")

# --- Rule 1: commit messages carry no trailers ------------------------------------------
#
# Defect: 2026-07-18. Nine commits reached public main carrying `Co-Authored-By` trailers.
#
# The history is not uniform and the accurate account matters. Of 108 commits before that session,
# 31 carried trailers and 77 did not; the practice drifted toward clean messages and every commit
# for a long stretch immediately preceding the session was clean. The settled convention was
# therefore observable only by reading the recent log, and an agent applying a tool default violated
# it without noticing.
#
# The rule is enforced from the convention-settled point rather than retroactively, because a guard
# that condemns history it was not written to govern is noise.

FORBIDDEN_TRAILER_PATTERN = re.compile(
    r"^(Co-Authored-By|Co-authored-by|Signed-off-by|Claude-Session|Generated-with):",
    re.MULTILINE,
)

# Commits already published with trailers. They are recorded rather than rewritten, because
# rewriting published history to hide a convention error is worse than the error. This list is a
# closed set: it may shrink if history is legitimately rebuilt, and it may never grow.
GRANDFATHERED_TRAILER_COMMITS = frozenset(
    {
        "dab4ba9",
        "6ddb438",
        "a3f1dc0",
        "1d55ea1",
        "39edd22",
        "62f6f45",
        "584194d",
        "1a76c81",
        "eaa271c",
    }
)


# The commit at which the no-trailer convention is treated as settled. Everything reachable from it
# is history this rule does not govern.
CONVENTION_SETTLED_AT = "0c9219c"


def check_no_commit_trailers() -> list[str]:
    """Every commit after the convention-settled point must be free of trailers."""
    log = subprocess.run(  # noqa: S603 - fixed trusted Git path and fixed argv
        [str(TRUSTED_GIT_PATH), "log", f"{CONVENTION_SETTLED_AT}..HEAD", "--format=%h%x00%B%x1e"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    problems: list[str] = []
    for record in log.split("\x1e"):
        if not record.strip():
            continue
        short, _, body = record.strip().partition("\x00")
        if short in GRANDFATHERED_TRAILER_COMMITS:
            continue
        found = FORBIDDEN_TRAILER_PATTERN.findall(body)
        if found:
            problems.append(f"commit {short} carries forbidden trailer(s): {sorted(set(found))}")
    return problems


# --- Rule 2: every recorded result is linked from the front page -------------------------
#
# Defect: 2026-07-18. Three RESULT documents existed and none was linked from README.md, while the
# README simultaneously asserted that no scientific result existed. A result that exists but is
# absent from the front page is a broken narrative, and this repository would have shipped one.
#
# Borrowed from the sibling Sentinel repository, which enforces the same invariant in CI.


def check_results_are_linked() -> list[str]:
    """Every `RESULT_*.md` under experiments must be linked from README.md."""
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    problems: list[str] = []
    for result in sorted(REPO_ROOT.glob("experiments/**/RESULT*.md")):
        relative = result.relative_to(REPO_ROOT).as_posix()
        if relative not in readme:
            problems.append(f"result not linked from README.md: {relative}")
    return problems


# --- Rule 3: every adjudication freeze is linked from the front page ---------------------
#
# A frozen protocol whose existence a reader cannot discover cannot be audited against the result it
# governs. Freezes are the mission's strongest evidence that a rule preceded its data, and burying
# them defeats their purpose.


def check_freezes_are_linked() -> list[str]:
    """Every `ADJUDICATION_FREEZE*.md` must be linked from README.md."""
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    problems: list[str] = []
    for freeze in sorted(REPO_ROOT.glob("experiments/**/ADJUDICATION_FREEZE*.md")):
        relative = freeze.relative_to(REPO_ROOT).as_posix()
        if relative not in readme:
            problems.append(f"freeze not linked from README.md: {relative}")
    return problems


# --- Rule 4: superseded claims may not reappear ------------------------------------------
#
# Defect: 2026-07-18. An adversarial audit found nine false or stale statements, including a private
# remote that had become public and an amendment count that was wrong in three files. Each was true
# when written. Staleness is the default state of prose, so each corrected claim is pinned here as a
# tripwire.
#
# Borrowed from Sentinel's forbidden-phrase guard.

FORBIDDEN_PHRASES: dict[str, tuple[str, ...]] = {
    "README.md": (
        "no scientific result exists",
        "Four owner-signed amendments",
        "16 real incidents",
        "the second\nconsecutive amendment",
    ),
    "CONTINUITY.md": (
        "The private remote is",
        "second consecutive amendment in that condition",
    ),
    "docs/IDENTITY.md": ("The repository remains private staging",),
}


def check_forbidden_phrases() -> list[str]:
    """A corrected claim must not reappear in the surface it was corrected in."""
    problems: list[str] = []
    for relative, phrases in FORBIDDEN_PHRASES.items():
        path = REPO_ROOT / relative
        if not path.exists():
            problems.append(f"forbidden-phrase surface is missing: {relative}")
            continue
        text = path.read_text(encoding="utf-8")
        for phrase in phrases:
            if phrase in text:
                problems.append(f"{relative} contains a superseded claim: {phrase!r}")
    return problems


# --- Rule 5: the guards must themselves be falsifiable -----------------------------------
#
# Defect: 2026-07-18. Three components were built, described as doing something, and found to do
# nothing, each having passed controls that could not fail on an inert component. A guard that
# cannot fail is not a guard.
#
# This rule checks that the surfaces the other rules inspect actually exist and are non-empty, so a
# renamed or deleted file produces a failure rather than silent universal agreement.


def check_guards_have_subjects() -> list[str]:
    """Every rule above must have a non-empty subject, or its agreement is vacuous."""
    problems: list[str] = []
    readme = REPO_ROOT / "README.md"
    if not readme.exists() or not readme.read_text(encoding="utf-8").strip():
        problems.append("README.md is missing or empty; link rules would pass vacuously")
    results = list(REPO_ROOT.glob("experiments/**/RESULT*.md"))
    freezes = list(REPO_ROOT.glob("experiments/**/ADJUDICATION_FREEZE*.md"))
    if not results:
        problems.append("no RESULT documents found; the result-link rule would pass vacuously")
    if not freezes:
        problems.append("no freeze documents found; the freeze-link rule would pass vacuously")
    return problems


RULES = (
    ("guards have subjects", check_guards_have_subjects),
    ("no commit trailers", check_no_commit_trailers),
    ("results linked from README", check_results_are_linked),
    ("freezes linked from README", check_freezes_are_linked),
    ("no superseded claims", check_forbidden_phrases),
)


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
        print(f"\n{failures} convention violation(s)")
        return 1
    print("\nCONVENTIONS_VERIFIED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
