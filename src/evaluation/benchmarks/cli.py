"""Click commands for fetching, preparing, and running external benchmarks."""

from __future__ import annotations

from pathlib import Path

import click

from src.evaluation.benchmarks.catalog import (
    BENCHMARKS,
    BenchmarkError,
    benchmark_root,
    upstream_path,
)
from src.evaluation.benchmarks.cwe_bench_java import prepare_cases
from src.evaluation.benchmarks.repository import fetch_benchmark, validate_checkout
from src.evaluation.benchmarks.runner import run_benchmark_command
from src.evaluation.benchmarks.validation import validate_benchmark_data
from src.utils.logger import configure_logging, get_logger

logger = get_logger()
BENCHMARK_CHOICE = click.Choice(sorted(BENCHMARKS))


def _store_option(function):
    return click.option(
        "--data-dir",
        type=click.Path(file_okay=False, path_type=Path),
        help="External benchmark store (default: .vtc-benchmarks or VTC_BENCHMARK_DIR).",
    )(function)


def _selection_options(function):
    options = [
        click.option("--seed", type=int, default=0, show_default=True),
        click.option(
            "--limit",
            type=click.IntRange(min=0),
            default=0,
            show_default=True,
            help="Reproducible sample size; 0 selects the complete filtered set.",
        ),
        click.option(
            "--all-cwes",
            is_flag=True,
            help="Include CWEs outside VTC's declared support set.",
        ),
        click.option(
            "--case",
            "case_ids",
            multiple=True,
            help="Case id, CVE, or project slug; repeat to select several.",
        ),
        click.option("--cwe", "cwes", multiple=True, help="CWE filter; repeatable."),
    ]
    for option in options:
        function = option(function)
    return function


@click.group()
def benchmark() -> None:
    """Manage and run pinned third-party benchmarks."""


@benchmark.command("list")
@_store_option
def list_benchmarks(data_dir: Path | None) -> None:
    """List adapters, pinned versions, and local checkout status."""
    root = benchmark_root(data_dir)
    click.echo("Benchmark         Unit       Status       Revision")
    for benchmark_id, spec in BENCHMARKS.items():
        checkout = upstream_path(root, benchmark_id)
        try:
            validate_checkout(spec, checkout)
            status = "ready"
        except BenchmarkError:
            status = "not fetched" if not checkout.exists() else "invalid"
        click.echo(
            f"{benchmark_id:<17} {spec.scoring_unit:<10} {status:<12} {spec.revision[:12]}"
        )


@benchmark.command("validate")
@click.argument("benchmark_id", required=False, type=BENCHMARK_CHOICE)
@_store_option
def validate_benchmarks(benchmark_id: str | None, data_dir: Path | None) -> None:
    """Validate complete pinned oracle metadata without running analysis."""
    root = benchmark_root(data_dir)
    benchmark_ids = [benchmark_id] if benchmark_id else list(BENCHMARKS)
    failed = False
    for current_id in benchmark_ids:
        try:
            checkout = upstream_path(root, current_id)
            validate_checkout(BENCHMARKS[current_id], checkout)
            result = validate_benchmark_data(current_id, checkout)
        except BenchmarkError as error:
            click.echo(f"{current_id}: INVALID")
            click.echo(f"  error: {error}")
            failed = True
            continue

        click.echo(f"{current_id}: {'VALID' if result.valid else 'INVALID'}")
        for key, value in result.statistics.items():
            click.echo(f"  {key}: {value}")
        for warning in result.warnings:
            click.echo(f"  warning: {warning}")
        for error in result.errors:
            click.echo(f"  error: {error}")
        failed = failed or not result.valid
    if failed:
        raise click.exceptions.Exit(1)


@benchmark.command()
@click.argument("benchmark_id", type=BENCHMARK_CHOICE)
@click.option("--force", is_flag=True, help="Replace a stale or invalid checkout.")
@_store_option
def fetch(benchmark_id: str, force: bool, data_dir: Path | None) -> None:
    """Fetch a benchmark metadata/source repository at its pinned revision."""
    configure_logging()
    root = benchmark_root(data_dir)
    with logger.contextualize(command="benchmark.fetch", target=benchmark_id):
        try:
            checkout = fetch_benchmark(benchmark_id, root, force=force)
        except BenchmarkError as error:
            raise click.ClickException(str(error)) from error
    click.echo(f"Fetched {benchmark_id} at {BENCHMARKS[benchmark_id].revision}")
    click.echo(f"Path: {checkout}")


@benchmark.command()
@click.argument("benchmark_id", type=click.Choice(["cwe-bench-java"]))
@click.option("--force", is_flag=True, help="Replace stale prepared project checkouts.")
@click.option("--include-tests", is_flag=True, help="Include test-source oracle targets.")
@_selection_options
@_store_option
def prepare(
    benchmark_id: str,
    force: bool,
    include_tests: bool,
    cwes: tuple[str, ...],
    case_ids: tuple[str, ...],
    all_cwes: bool,
    limit: int,
    seed: int,
    data_dir: Path | None,
) -> None:
    """Fetch vulnerable project revisions needed by CWE-Bench-Java."""
    configure_logging()
    root = benchmark_root(data_dir)
    checkout = upstream_path(root, benchmark_id)
    with logger.contextualize(command="benchmark.prepare", target=benchmark_id):
        try:
            validate_checkout(BENCHMARKS[benchmark_id], checkout)
            summary = prepare_cases(
                checkout,
                root,
                cwes=cwes,
                case_ids=case_ids,
                all_cwes=all_cwes,
                limit=limit,
                seed=seed,
                include_tests=include_tests,
                force=force,
            )
        except BenchmarkError as error:
            raise click.ClickException(str(error)) from error
    click.echo(
        f"Prepared {len(summary['prepared'])} / {summary['selected']} selected cases"
    )
    skipped = summary["skipped_without_localization_oracle"]
    if skipped:
        click.echo(f"Skipped without localization oracle: {len(skipped)}")
    out_of_scope = summary["skipped_with_oracle_out_of_scope"]
    if out_of_scope:
        click.echo(f"Skipped with test-only oracle: {len(out_of_scope)}")
    unavailable = summary["skipped_without_vulnerable_revision"]
    if unavailable:
        click.echo(f"Skipped without vulnerable revision: {len(unavailable)}")


@benchmark.command()
@click.argument("benchmark_id", type=BENCHMARK_CHOICE)
@click.option(
    "--backend",
    type=click.Choice(["llm", "static", "hybrid"]),
    default="llm",
    show_default=True,
)
@click.option(
    "--llm-analysis-mode",
    type=click.Choice(["targeted", "exhaustive"]),
    default="targeted",
    show_default=True,
)
@click.option(
    "--batch-size",
    type=click.IntRange(min=1),
    default=64,
    show_default=True,
    help="OWASP cases per isolated project-mode batch.",
)
@click.option("--include-tests", is_flag=True, help="Include test sources in real projects.")
@click.option("--refresh-specs", is_flag=True, help="Ignore cached Stage 1 results.")
@click.option("--fail-fast", is_flag=True, help="Stop on the first analysis error.")
@click.option(
    "--retry-errors",
    is_flag=True,
    help="CWE-Bench: rerun checkpoint rows whose status is execution error.",
)
@click.option(
    "--max-concurrent-files",
    type=click.IntRange(min=1),
    help="Override concurrent Stage 1 file extractions for this run.",
)
@click.option(
    "--max-concurrent-functions",
    type=click.IntRange(min=1),
    help="Override concurrent function batches within each file for this run.",
)
@click.option(
    "--max-concurrent-llm-requests",
    type=click.IntRange(min=1),
    help="Override the global in-flight OpenAI/Ollama request cap.",
)
@click.option("--phase-label", help="Safe label used for default report filenames.")
@click.option("--save", type=click.Path(dir_okay=False, path_type=Path))
@click.option("--report-md", type=click.Path(dir_okay=False, path_type=Path))
@_selection_options
@_store_option
def run(
    benchmark_id: str,
    backend: str,
    llm_analysis_mode: str,
    batch_size: int,
    include_tests: bool,
    refresh_specs: bool,
    fail_fast: bool,
    retry_errors: bool,
    max_concurrent_files: int | None,
    max_concurrent_functions: int | None,
    max_concurrent_llm_requests: int | None,
    phase_label: str | None,
    save: Path | None,
    report_md: Path | None,
    cwes: tuple[str, ...],
    case_ids: tuple[str, ...],
    all_cwes: bool,
    limit: int,
    seed: int,
    data_dir: Path | None,
) -> None:
    """Run a pinned benchmark with its suite-specific honest scorer."""
    configure_logging()
    root = benchmark_root(data_dir)
    with logger.contextualize(command="benchmark.run", target=benchmark_id):
        try:
            run_benchmark_command(
                benchmark_id,
                root,
                backend=backend,
                llm_analysis_mode=llm_analysis_mode,
                cwes=cwes,
                case_ids=case_ids,
                all_cwes=all_cwes,
                limit=limit,
                seed=seed,
                batch_size=batch_size,
                include_tests=include_tests,
                refresh_specs=refresh_specs,
                fail_fast=fail_fast,
                retry_errors=retry_errors,
                max_concurrent_files=max_concurrent_files,
                max_concurrent_functions=max_concurrent_functions,
                max_concurrent_llm_requests=max_concurrent_llm_requests,
                phase_label=phase_label,
                save=save,
                report_md=report_md,
            )
        except (BenchmarkError, OSError, ValueError) as error:
            raise click.ClickException(str(error)) from error
