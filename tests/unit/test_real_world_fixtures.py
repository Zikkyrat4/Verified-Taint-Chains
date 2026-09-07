"""Structural validation of `tests/fixtures/real_world/<project>/ground_truth.json`.

Lightweight schema checks — no LLM, no pipeline. Run on every CI to catch typos
when adding new projects.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REAL_WORLD = Path(__file__).resolve().parent.parent / "fixtures" / "real_world"

# Allowed `vuln_type` values must align with the exact labels accepted by the
# evaluator and the VulnerabilityType enum extensions.
_ALLOWED_VULN_TYPES = {
    "xss",
    "sql_injection",
    "command_injection",
    "path_traversal",
    "xxe",
    "ssrf",
    "deserialization",
    "open_redirect",
    "code_injection",
}


def _projects() -> list[Path]:
    if not REAL_WORLD.exists():
        return []
    return sorted(
        p for p in REAL_WORLD.iterdir() if p.is_dir() and (p / "ground_truth.json").exists()
    )


@pytest.fixture(scope="module")
def projects() -> list[Path]:
    return _projects()


def test_at_least_one_project_present(projects: list[Path]) -> None:
    assert projects, f"No real_world projects under {REAL_WORLD}"


@pytest.mark.parametrize("project", _projects(), ids=lambda p: p.name)
def test_ground_truth_parses(project: Path) -> None:
    truth = json.loads((project / "ground_truth.json").read_text())
    assert isinstance(truth, dict), f"{project.name}: ground_truth.json must be an object"
    assert "files" in truth and isinstance(truth["files"], dict), (
        f"{project.name}: ground_truth.json must contain a 'files' object"
    )
    assert truth["files"], f"{project.name}: 'files' must not be empty"


@pytest.mark.parametrize("project", _projects(), ids=lambda p: p.name)
def test_referenced_files_exist(project: Path) -> None:
    truth = json.loads((project / "ground_truth.json").read_text())
    for rel in truth["files"]:
        assert (project / rel).is_file(), (
            f"{project.name}: ground_truth references missing file '{rel}'"
        )


@pytest.mark.parametrize("project", _projects(), ids=lambda p: p.name)
def test_true_positive_schema(project: Path) -> None:
    truth = json.loads((project / "ground_truth.json").read_text())
    for rel, entry in truth["files"].items():
        for tp in entry.get("true_positives", []):
            for required in ("source_var", "sink_var", "vuln_type"):
                assert tp.get(required), (
                    f"{project.name}/{rel}: TP missing '{required}' in {tp}"
                )
            assert tp["vuln_type"] in _ALLOWED_VULN_TYPES, (
                f"{project.name}/{rel}: vuln_type '{tp['vuln_type']}' not in allowlist "
                f"{sorted(_ALLOWED_VULN_TYPES)}"
            )


@pytest.mark.parametrize("project", _projects(), ids=lambda p: p.name)
def test_fp_pattern_schema(project: Path) -> None:
    truth = json.loads((project / "ground_truth.json").read_text())
    for rel, entry in truth["files"].items():
        for fp in entry.get("false_positive_patterns", []):
            assert any(k in fp for k in ("source_var", "sink_var", "source_pattern", "sink_pattern")), (
                f"{project.name}/{rel}: FP entry must have at least one of "
                f"source_var/sink_var/source_pattern/sink_pattern: {fp}"
            )
            assert fp.get("reason"), f"{project.name}/{rel}: FP entry missing 'reason': {fp}"
