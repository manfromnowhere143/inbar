"""Thin direct runner for the frozen initial experiment."""

from __future__ import annotations

from pathlib import Path

from fieldtrue.experiment import run_iter000

if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    run_iter000(root, command=("python", "harness/runner.py"))
