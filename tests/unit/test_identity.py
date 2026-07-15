from __future__ import annotations

import json
from pathlib import Path


def _repo() -> Path:
    return Path(__file__).resolve().parents[2]


def test_active_machine_identity_is_inbar_with_an_explicit_legacy_boundary() -> None:
    repo = _repo()
    contract = json.loads((repo / "mission" / "contract.json").read_text(encoding="utf-8"))
    loop = json.loads((repo / "mission" / "loop.json").read_text(encoding="utf-8"))
    identity = json.loads((repo / "mission" / "name.json").read_text(encoding="utf-8"))

    assert contract["mission_id"] == loop["mission_id"] == "inbar"
    assert contract["name"] == identity["canonical_name"] == "Inbar"
    assert identity["canonical_slug"] == "inbar"
    assert contract["legacy_protocol_namespace"] == "fieldtrue"
    assert identity["legacy_boundary"]["name"] == "Fieldtrue"


def test_current_facing_documents_identify_inbar() -> None:
    repo = _repo()
    required_text = {
        "README.md": "# Inbar\n",
        "CITATION.cff": (
            'title: "Inbar: Physical Causal Evidence and Verified Intervention Research"'
        ),
        "docs/IDENTITY.md": "# Inbar Identity\n",
        "CONTRIBUTING.md": "Inbar is a preregistered, single-owner research mission.",
        "SECURITY.md": "Inbar is pre-release research software.",
        "AGENTS.md": "# Inbar Agent Bootstrap\n",
        "CONTINUITY.md": "# Inbar Continuity\n",
        "HANDOFF.md": "# Inbar Mission Handoff\n",
        "src/fieldtrue/__init__.py": '"""Inbar research software',
    }
    for relative, expected in required_text.items():
        assert expected in (repo / relative).read_text(encoding="utf-8"), relative

    legacy_free = (
        "README.md",
        "CITATION.cff",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "AGENTS.md",
        "tests/__init__.py",
        "tests/unit/__init__.py",
        "tests/integration/__init__.py",
    )
    for relative in legacy_free:
        assert "Fieldtrue" not in (repo / relative).read_text(encoding="utf-8"), relative


def test_preferred_commands_are_inbar_while_import_compatibility_remains() -> None:
    repo = _repo()
    workflow = (repo / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    agents = (repo / "AGENTS.md").read_text(encoding="utf-8")
    contributing = (repo / "CONTRIBUTING.md").read_text(encoding="utf-8")
    project = (repo / "pyproject.toml").read_text(encoding="utf-8")

    assert "uv run fieldtrue" not in workflow
    assert "uv run fieldtrue" not in agents
    assert "uv run fieldtrue" not in contributing
    assert "import fieldtrue" in workflow
    assert 'fieldtrue = "fieldtrue.cli:main"' in project
    assert 'inbar = "fieldtrue.cli:main"' in project

    adapter = (repo / "src" / "fieldtrue" / "adapters" / "adapt.py").read_text(encoding="utf-8")
    assert '"User-Agent": "inbar/' in adapter
    assert '"User-Agent": "fieldtrue/' not in adapter
