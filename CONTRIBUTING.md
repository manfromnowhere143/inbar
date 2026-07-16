# Contributing

Inbar is a preregistered, single-owner research mission. Contributions are reviewed for both
software correctness and their effect on the scientific contract.

## Before changing code

1. Read `AGENTS.md`, `mission/contract.json`, `PREREGISTRATION.md`, and the active iteration's
   `HYPOTHESIS.md`.
2. Do not modify a frozen preregistration or reinterpret a gate after observing its outcome.
3. State whether the change affects evidence visibility, truth, approvals, execution authority,
   estimands, controls, verdicts, or permitted claims.
4. Record prospective protocol changes as explicit amendments before execution.

## Local verification

```bash
uv sync --link-mode copy --reinstall
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest --cov --cov-report=term-missing
uv run inbar schemas check
uv run inbar mission validate --expect-failure iter001-acquisition-contract
git diff --check
```

Changes to a claim-bearing gate require a passing positive control, a deliberately broken or
placebo negative control, and an updated `protocol/gate_controls` entry. Tests must exercise the
same executable path that produces the research verdict.

Do not commit raw third-party data, generated run directories, local keys, credentials, or secrets.
Null, blocked, invalid, interrupted, and correction outcomes must remain visible.
