"""Java source discovery shared by the CLI and benchmark runners."""

from __future__ import annotations

import re
from pathlib import Path

# Build output often duplicates ``src/main``. Generated and vendored trees are
# excluded as well because they are not application source under evaluation.
EXCLUDED_DIRS = frozenset(
    {
        "target",
        "build",
        "out",
        "bin",
        "dist",
        "node_modules",
        "generated-sources",
        "generated",
        "generated-test-sources",
        ".git",
        ".idea",
        ".gradle",
        ".mvn",
        ".settings",
        ".svn",
    }
)

_TEST_FILE_RE = re.compile(r"(?:Test|Tests|IT|TestCase)\.java$")
_TEST_DIRS = frozenset(
    {
        "test",
        "tests",
        "devtest",
        "devtests",
        "integration-test",
        "integration-tests",
        "integrationtest",
        "integrationtests",
        "testfixtures",
        "androidtest",
    }
)


def is_test_path(rel_parts: tuple[str, ...], name: str) -> bool:
    """Return whether a relative path follows a conventional Java test layout."""
    normalized = tuple(part.lower().replace("_", "-") for part in rel_parts[:-1])
    if any(part in _TEST_DIRS for part in normalized):
        return True
    for index in range(len(rel_parts) - 1):
        if (
            rel_parts[index].lower() == "src"
            and rel_parts[index + 1].lower().replace("_", "-") in _TEST_DIRS
        ):
            return True
    return bool(_TEST_FILE_RE.search(name))


def find_java_files(path: str | Path, include_tests: bool = False) -> list[str]:
    """Find Java application sources below ``path`` in deterministic order."""
    root = Path(path)
    if root.is_file():
        return [str(root)]

    result: list[str] = []
    for file_path in root.rglob("*.java"):
        rel_parts = file_path.relative_to(root).parts
        if any(part in EXCLUDED_DIRS for part in rel_parts[:-1]):
            continue
        if not include_tests and is_test_path(rel_parts, file_path.name):
            continue
        result.append(str(file_path))
    return sorted(result)


def count_all_java(path: str | Path) -> int:
    """Count Java files before source-scope exclusions are applied."""
    root = Path(path)
    if root.is_file():
        return 1
    return sum(1 for _ in root.rglob("*.java"))
