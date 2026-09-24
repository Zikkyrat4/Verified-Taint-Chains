"""Safe, pinned Git checkout management for external benchmarks."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterable
from pathlib import Path

from src.evaluation.benchmarks.catalog import (
    BENCHMARKS,
    BenchmarkError,
    BenchmarkSpec,
    upstream_path,
)


def _git(args: Iterable[str], cwd: Path | None = None) -> str:
    command = ["git", *args]
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            check=True,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired as error:
        raise BenchmarkError(f"Git command timed out: {' '.join(command)}") from error
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or error.stdout or str(error)).strip()
        raise BenchmarkError(f"Git command failed: {' '.join(command)}\n{detail}") from error
    return completed.stdout.strip()


def checkout_revision(
    repository: str,
    revision: str,
    destination: Path,
    *,
    force: bool = False,
) -> Path:
    """Materialize exactly one immutable Git revision using an atomic rename."""
    if destination.exists():
        try:
            current = _git(["rev-parse", "HEAD"], cwd=destination)
        except BenchmarkError:
            current = ""
        if current == revision:
            return destination
        if not force:
            raise BenchmarkError(
                f"{destination} exists at revision {current or 'unknown'}; "
                "use --force to replace it"
            )
        shutil.rmtree(destination)

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=destination.parent)
    )
    try:
        _git(["init", "--quiet"], cwd=temporary)
        _git(["remote", "add", "origin", repository], cwd=temporary)
        _git(["fetch", "--depth", "1", "origin", revision], cwd=temporary)
        _git(["checkout", "--quiet", "--detach", "FETCH_HEAD"], cwd=temporary)
        actual = _git(["rev-parse", "HEAD"], cwd=temporary)
        if actual != revision:
            raise BenchmarkError(
                f"Revision verification failed for {repository}: {actual} != {revision}"
            )
        temporary.replace(destination)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return destination


def validate_checkout(spec: BenchmarkSpec, checkout: Path) -> None:
    """Validate both the Git pin and the adapter's required input files."""
    if not checkout.is_dir():
        raise BenchmarkError(
            f"{spec.benchmark_id} is not fetched; run "
            f"`vtc benchmark fetch {spec.benchmark_id}` first"
        )
    actual = _git(["rev-parse", "HEAD"], cwd=checkout)
    if actual != spec.revision:
        raise BenchmarkError(
            f"Unexpected {spec.benchmark_id} revision {actual}; expected {spec.revision}"
        )
    missing = [relative for relative in spec.required_paths if not (checkout / relative).exists()]
    if missing:
        raise BenchmarkError(
            f"Invalid {spec.benchmark_id} checkout; missing: {', '.join(missing)}"
        )


def validate_revision(checkout: Path, revision: str, label: str) -> None:
    """Validate a prepared case without performing a network operation."""
    if not checkout.is_dir():
        raise BenchmarkError(f"Prepared source is missing for {label}: {checkout}")
    actual = _git(["rev-parse", "HEAD"], cwd=checkout)
    if actual != revision:
        raise BenchmarkError(
            f"Prepared source for {label} is at {actual}; expected {revision}"
        )


def fetch_benchmark(benchmark_id: str, root: Path, *, force: bool = False) -> Path:
    """Fetch and validate a benchmark catalog checkout."""
    spec = BENCHMARKS[benchmark_id]
    checkout = checkout_revision(
        spec.repository,
        spec.revision,
        upstream_path(root, benchmark_id),
        force=force,
    )
    validate_checkout(spec, checkout)
    return checkout
