"""CLI-интерфейс VTC — анализ безопасности Java-кода."""

import asyncio
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import click

from src.core.config import load_config_from_env
from src.core.models import SinkCategory
from src.evaluation.engine import run_evaluation_command
from src.pipeline.orchestrator import SimplePipeline
from src.stage1_llm_inference.spec_cache import default_cache_dir
from src.utils.logger import configure_logging, get_logger

logger = get_logger()


# Directory names that are never application source: build output (which often
# duplicates all of src/main), generated code, vendored deps, IDE/SCM metadata.
# Matched as path components — analyzing them just wastes an LLM call per file.
_EXCLUDED_DIRS = frozenset({
    "target", "build", "out", "bin", "dist",
    "node_modules", "generated-sources", "generated", "generated-test-sources",
    ".git", ".idea", ".gradle", ".mvn", ".settings", ".svn",
})

# Conventional test file names (JUnit/Maven Surefire/Failsafe).
_TEST_FILE_RE = re.compile(r"(?:Test|Tests|IT|TestCase)\.java$")


def _is_test_path(rel_parts: tuple, name: str) -> bool:
    """True if a file is test code (Maven/Gradle layout or conventional name)."""
    # Maven/Gradle test source roots: src/test/**, src/integration-test/**, ...
    for i in range(len(rel_parts) - 1):
        if rel_parts[i] == "src" and rel_parts[i + 1] in (
            "test", "integration-test", "testFixtures", "androidTest"
        ):
            return True
    return bool(_TEST_FILE_RE.search(name))


def _find_java_files(path: str, include_tests: bool = False) -> List[str]:
    """Find .java files recursively, skipping non-application code.

    Always skips build output / generated / vendored / IDE-SCM directories
    (see ``_EXCLUDED_DIRS``). Test code (``src/test/**``, ``*Test.java``, ...)
    is also skipped unless ``include_tests=True``.

    Excluding these is standard scoping of the application under analysis — it
    never hides a source/sink in production code — and it avoids wasting an LLM
    call per file on duplicated build output and generated/vendored code.

    A single file path is returned as-is (explicit targeting wins).
    """
    p = Path(path)
    if p.is_file():
        return [str(p)]

    result: List[str] = []
    for f in p.rglob("*.java"):
        rel_parts = f.relative_to(p).parts
        # Skip if any *directory* component (exclude the filename) is excluded.
        if any(part in _EXCLUDED_DIRS for part in rel_parts[:-1]):
            continue
        if not include_tests and _is_test_path(rel_parts, f.name):
            continue
        result.append(str(f))
    return sorted(result)


def _count_all_java(path: str) -> int:
    """Total .java files under a directory, before any exclusion (for display)."""
    p = Path(path)
    if p.is_file():
        return 1
    return sum(1 for _ in p.rglob("*.java"))


def _apply_cache_settings(
    config, source_path: str, no_cache: bool, cache_dir: Optional[str]
) -> None:
    """Resolve final cache settings into ``config``.

    CLI flags win over env, env wins over defaults. Default cache_dir is
    resolved against the *target* source path (`<source_path>/.vtc-cache`)
    because the orchestrator doesn't know the source path at __init__ time.
    """
    if no_cache:
        config.cache_enabled = False
        config.cache_dir = None
        return
    if not config.cache_enabled:
        # Env says off and no CLI override turns it on; leave as is.
        return
    if cache_dir:
        config.cache_dir = cache_dir
    elif not config.cache_dir:
        config.cache_dir = str(default_cache_dir(source_path))


def _cache_status_line(config) -> str:
    """Human-readable Cache: ... line for the CONFIGURATION block."""
    if not config.cache_enabled:
        return "disabled"
    where = config.cache_dir or "(unset)"
    return f"enabled ({where})"


def _display_cache_summary(pipeline) -> None:
    """Print cache hit/miss/write stats after a run.

    Silent when no cache was wired or no Stage 1 calls happened.
    """
    cache = getattr(pipeline, "spec_cache", None)
    if cache is None:
        return
    total = cache.stats.hits + cache.stats.misses
    if total == 0:
        return
    click.echo(f"\n{cache.summary_line()}")


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """VTC — инструмент анализа безопасности Java-кода.

    \b
    4-ступенчатый пайплайн:
      1. LLM-инференс: извлечение source/sink из кода
      2. Построение графа: tree-sitter AST + LLM-обогащение
      3. Верификация: CFG-проверка достижимости (опц. Z3)
      4. Объяснение: генерация описаний и рекомендаций

    \b
    Поддерживаемые уязвимости:
      SQL Injection, XSS, Command Injection,
      Path Traversal, XXE, SSRF

    \b
    Логи: stderr + ~/.local/state/vtc/vtc.log (уровень задаёт LOG_LEVEL)

    \b
    Примеры:
      vtc analyze code.java
      vtc analyze src/main/java/ -o report.json -v
      vtc analyze code.java --llm-provider ollama
    """
    pass


@cli.command()
@click.option(
    "--project",
    type=str,
    help="Проект из tests/fixtures/real_world/.",
)
@click.option(
    "--all-projects",
    is_flag=True,
    help="Запустить benchmark для всех проектов.",
)
@click.option(
    "--fixtures-dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Явный каталог с ground_truth.json и Java-фикстурами.",
)
@click.option(
    "--save",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Путь для JSON-отчёта.",
)
@click.option(
    "--report-md",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Путь для Markdown-отчёта.",
)
@click.option(
    "--baseline",
    is_flag=True,
    help="Использовать метку baseline для автоматически сохранённых отчётов.",
)
@click.option(
    "--phase-label",
    type=str,
    help="Безопасная метка имени автоматически сохранённых отчётов.",
)
@click.option(
    "--diff",
    "diff_paths",
    nargs=2,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    metavar="BASELINE AFTER",
    help="Сравнить два JSON-отчёта без запуска анализа.",
)
@click.option(
    "--refresh-specs",
    is_flag=True,
    help="Не читать Stage 1 cache и получить свежие LLM-ответы.",
)
@click.option(
    "--analysis-backend",
    "--backend",
    type=click.Choice(["llm", "static", "hybrid"]),
    help="Источник endpoints: llm, static или hybrid.",
)
@click.option(
    "--llm-analysis-mode",
    type=click.Choice(["targeted", "exhaustive"]),
    help="Охват LLM; для static игнорируется.",
)
def evaluate(
    project: Optional[str],
    all_projects: bool,
    fixtures_dir: Optional[Path],
    save: Optional[Path],
    report_md: Optional[Path],
    baseline: bool,
    phase_label: Optional[str],
    diff_paths: Optional[tuple[Path, Path]],
    refresh_specs: bool,
    analysis_backend: Optional[str],
    llm_analysis_mode: Optional[str],
) -> None:
    """Запустить строгую оценку VTC по размеченным Java-фикстурам.

    \b
    Примеры:
      vtc evaluate --all-projects --backend llm --phase-label llm-honest
      vtc evaluate --project keycloak --backend static
      vtc evaluate --diff baseline.json candidate.json
    """
    configure_logging()
    target = (
        str(fixtures_dir)
        if fixtures_dir
        else project or ("all-projects" if all_projects else "diff")
    )
    with logger.contextualize(command="evaluate", target=target):
        try:
            exit_code = run_evaluation_command(
                fixtures_dir=fixtures_dir,
                project=project,
                all_projects=all_projects,
                save=save,
                report_md=report_md,
                baseline=baseline,
                phase_label=phase_label,
                diff_paths=diff_paths,
                refresh_specs=refresh_specs,
                analysis_backend=analysis_backend,
                llm_analysis_mode=llm_analysis_mode,
            )
        except SystemExit as error:
            if str(error):
                raise click.ClickException(str(error)) from error
            raise click.exceptions.Exit(error.code or 1) from error
        except (OSError, ValueError) as error:
            raise click.ClickException(str(error)) from error

    if exit_code:
        raise click.exceptions.Exit(exit_code)


@cli.command()
@click.argument("source_path", type=click.Path(exists=True))
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Сохранить результат в JSON-файл.",
)
@click.option(
    "--verification-level",
    type=click.Choice(["cfg", "symbolic", "both"]),
    help="Уровень верификации: cfg (быстрый), symbolic (Z3), both (оба).",
)
@click.option(
    "--pathfinding-algorithm",
    type=click.Choice(["astar", "bfs"]),
    help="Алгоритм поиска путей: astar (с семантической эвристикой) или bfs.",
)
@click.option(
    "--llm-provider",
    type=click.Choice(["openai", "ollama"]),
    help="LLM-провайдер: openai или ollama.",
)
@click.option(
    "--llm-model",
    type=str,
    help="Название LLM-модели (например gpt-4-turbo, llama3.2:latest).",
)
@click.option(
    "--max-files",
    type=int,
    default=0,
    help="Макс. кол-во файлов для анализа в project mode (0 = без лимита).",
)
@click.option(
    "--max-concurrent",
    type=int,
    default=0,
    help="Макс. параллельных LLM-запросов (0 = из конфигурации).",
)
@click.option(
    "--include-tests",
    is_flag=True,
    help="Анализировать также тест-код (src/test/**, *Test.java). По умолчанию пропускается.",
)
@click.option(
    "--no-cache",
    is_flag=True,
    help="Отключить persistent кэш Stage 1 (.vtc-cache/). По умолчанию включён.",
)
@click.option(
    "--cache-dir",
    type=click.Path(),
    default=None,
    help="Путь к каталогу кэша. По умолчанию <source_path>/.vtc-cache.",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Подробный вывод и DEBUG-логи: пути, объяснения, CWE.",
)
def analyze(
    source_path: str,
    output: Optional[str],
    verification_level: Optional[str],
    pathfinding_algorithm: Optional[str],
    llm_provider: Optional[str],
    llm_model: Optional[str],
    max_files: int,
    max_concurrent: int,
    include_tests: bool,
    no_cache: bool,
    cache_dir: Optional[str],
    verbose: bool,
):
    """Анализ Java-файла или директории на уязвимости.

    \b
    Логи пишутся в stderr и пользовательский state-каталог; `-v` включает DEBUG.

    \b
    Примеры:
      vtc analyze code.java
      vtc analyze code.java -o results.json -v
      vtc analyze src/main/java/ -o report.json
      vtc analyze code.java --llm-provider ollama --llm-model llama3.2:latest
      vtc analyze code.java --verification-level both --pathfinding-algorithm bfs
      vtc analyze src/ --max-files 50 --max-concurrent 2
    """
    configure_logging(level="DEBUG" if verbose else None)

    with logger.contextualize(command="analyze", target=source_path):
        asyncio.run(
            _analyze(
                source_path,
                output,
                verification_level,
                pathfinding_algorithm,
                llm_provider,
                llm_model,
                max_files,
                max_concurrent,
                include_tests,
                no_cache,
                cache_dir,
                verbose,
            )
        )


async def _analyze(
    source_path: str,
    output: Optional[str],
    verification_level: Optional[str],
    pathfinding_algorithm: Optional[str],
    llm_provider: Optional[str],
    llm_model: Optional[str],
    max_files: int,
    max_concurrent: int,
    include_tests: bool,
    no_cache: bool,
    cache_dir: Optional[str],
    verbose: bool,
):
    """Внутренняя async-функция анализа."""
    try:
        # Load configuration from environment
        config = load_config_from_env()

        # Override with command-line options
        if verification_level:
            config.verification_level = verification_level
            # Sync symbolic_execution_enabled
            if verification_level in ("symbolic", "both"):
                config.symbolic_execution_enabled = True

        if pathfinding_algorithm:
            config.pathfinding_algorithm = pathfinding_algorithm

        if llm_provider:
            config.llm_provider = llm_provider

        if llm_model:
            config.llm_model = llm_model

        if max_files > 0:
            config.max_files = max_files

        if max_concurrent > 0:
            config.max_concurrent_files = max_concurrent

        # Resolve cache settings. CLI flags override env. cache_dir default
        # depends on the target source path, so it can only be picked here.
        _apply_cache_settings(config, source_path, no_cache, cache_dir)

        # Find Java files (skips build/generated/vendor/test code by default)
        java_files = _find_java_files(source_path, include_tests=include_tests)
        if not java_files:
            click.echo("No .java files found.")
            sys.exit(1)

        is_multi_file = len(java_files) > 1
        skipped = _count_all_java(source_path) - len(java_files)

        # Display configuration
        click.echo(f"\n{'='*70}")
        click.echo("CONFIGURATION")
        click.echo(f"{'='*70}")
        click.echo(f"LLM Provider: {config.llm_provider}")
        click.echo(f"LLM Model: {config.llm_model}")
        click.echo(f"Pathfinding: {config.pathfinding_algorithm}")
        click.echo(f"Verification: {config.verification_level}")
        click.echo(f"Graph builder: {'LLM-enriched' if config.use_llm_graph_builder else 'regex-only'}")
        click.echo(f"Min confidence: {config.min_confidence}")
        click.echo(f"Cache: {_cache_status_line(config)}")
        click.echo(f"Source: {source_path}")
        if is_multi_file:
            click.echo(f"Files to analyze: {len(java_files)}")
            if skipped > 0:
                click.echo(f"Skipped (build/generated/vendor{'' if include_tests else '/test'}): {skipped}")
        click.echo(f"{'='*70}\n")

        # Create pipeline (reused for all files)
        pipeline = SimplePipeline(config)

        # Stage 1 snapshot: after the longest (LLM) stage completes, dump the
        # source/sink inventory so a Stage 2-4 crash leaves a triagable file on
        # disk. The final _save_results overwrites this with the full result.
        stage1_callback = None
        if output:
            def _on_stage1(snapshot: Dict[str, Any]):
                try:
                    _save_results_stage1_snapshot(
                        output, snapshot, is_multi_file=is_multi_file
                    )
                except OSError as snap_err:
                    logger.warning(
                        f"Failed to write Stage 1 snapshot: {snap_err}"
                    )
            stage1_callback = _on_stage1

        if is_multi_file:
            # Project mode: unified cross-file analysis
            result = await pipeline.run_project(
                java_files,
                show_progress=sys.stderr.isatty(),
                on_stage1_complete=stage1_callback,
            )
        else:
            # Single-file mode
            result = await pipeline.run(
                java_files[0],
                on_stage1_complete=stage1_callback,
            )

        _display_results(result, verbose)
        _display_cache_summary(pipeline)

        if output:
            _save_results(result, output)
            click.echo(f"\n✓ Results saved to: {output}")

        # Exit with success
        sys.exit(0)

    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        click.echo(f"\n✗ Error: {str(e)}", err=True)
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.argument("source_path", type=click.Path(exists=True))
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Сохранить инвентарь синков в JSON-файл.",
)
@click.option(
    "--llm-provider",
    type=click.Choice(["openai", "ollama"]),
    help="LLM-провайдер: openai или ollama.",
)
@click.option(
    "--llm-model",
    type=str,
    help="Название LLM-модели (например gpt-4-turbo, llama3.2:latest).",
)
@click.option(
    "--max-files",
    type=int,
    default=0,
    help="Макс. кол-во файлов для анализа (0 = без лимита).",
)
@click.option(
    "--max-concurrent",
    type=int,
    default=0,
    help="Макс. параллельных LLM-запросов (0 = из конфигурации).",
)
@click.option(
    "--include-tests",
    is_flag=True,
    help="Анализировать также тест-код (src/test/**, *Test.java). По умолчанию пропускается.",
)
@click.option(
    "--no-cache",
    is_flag=True,
    help="Отключить persistent кэш Stage 1 (.vtc-cache/). По умолчанию включён.",
)
@click.option(
    "--cache-dir",
    type=click.Path(),
    default=None,
    help="Путь к каталогу кэша. По умолчанию <source_path>/.vtc-cache.",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Подробный вывод и DEBUG-логи: code snippet, CWE, reasoning.",
)
def sinks(
    source_path: str,
    output: Optional[str],
    llm_provider: Optional[str],
    llm_model: Optional[str],
    max_files: int,
    max_concurrent: int,
    include_tests: bool,
    no_cache: bool,
    cache_dir: Optional[str],
    verbose: bool,
):
    """Собрать инвентарь ОПАСНЫХ синков по всему проекту (только Stage 1).

    \b
    В отличие от `analyze`, не строит граф и не ищет цепочки source→sink:
    выполняет только извлечение синков (Stage 1) и печатает опасные синки,
    даже если для них не найден источник. Полезно для 0-day-триажа.

    \b
    «Опасный» = sink_category != benign И confidence >= min_confidence.
    Категория UNKNOWN сохраняется (незнакомый API — возможный 0-day).

    \b
    Примеры:
      vtc sinks src/main/java/
      vtc sinks src/ -o sinks.json -v
      vtc sinks Foo.java --llm-provider ollama
    """
    configure_logging(level="DEBUG" if verbose else None)

    with logger.contextualize(command="sinks", target=source_path):
        asyncio.run(
            _sinks(
                source_path,
                output,
                llm_provider,
                llm_model,
                max_files,
                max_concurrent,
                include_tests,
                no_cache,
                cache_dir,
                verbose,
            )
        )


async def _sinks(
    source_path: str,
    output: Optional[str],
    llm_provider: Optional[str],
    llm_model: Optional[str],
    max_files: int,
    max_concurrent: int,
    include_tests: bool,
    no_cache: bool,
    cache_dir: Optional[str],
    verbose: bool,
):
    """Внутренняя async-функция инвентаря синков."""
    try:
        config = load_config_from_env()

        if llm_provider:
            config.llm_provider = llm_provider
        if llm_model:
            config.llm_model = llm_model
        if max_files > 0:
            config.max_files = max_files
        if max_concurrent > 0:
            config.max_concurrent_files = max_concurrent

        _apply_cache_settings(config, source_path, no_cache, cache_dir)

        java_files = _find_java_files(source_path, include_tests=include_tests)
        if not java_files:
            click.echo("No .java files found.")
            sys.exit(1)

        skipped = _count_all_java(source_path) - len(java_files)

        click.echo(f"\n{'='*70}")
        click.echo("CONFIGURATION")
        click.echo(f"{'='*70}")
        click.echo(f"LLM Provider: {config.llm_provider}")
        click.echo(f"LLM Model: {config.llm_model}")
        click.echo(f"Min confidence: {config.min_confidence}")
        click.echo("Mode: sink inventory (Stage 1 only)")
        click.echo(f"Cache: {_cache_status_line(config)}")
        click.echo(f"Source: {source_path}")
        click.echo(f"Files to analyze: {len(java_files)}")
        if skipped > 0:
            click.echo(f"Skipped (build/generated/vendor{'' if include_tests else '/test'}): {skipped}")
        click.echo(f"{'='*70}\n")

        pipeline = SimplePipeline(config)

        # Incremental save: after each file's Stage 1 finishes, rewrite the
        # output JSON atomically (.tmp + os.replace) so a Ctrl-C or crash on a
        # long real-project run leaves a valid partial result on disk.
        collected_running: List[Any] = []
        files_done = [0]

        def _on_file_done(file_path: str, sinks: list):
            files_done[0] += 1
            for snk in sinks:
                collected_running.append((file_path, snk))
            if output:
                try:
                    _save_sinks_snapshot(
                        output,
                        collected_running,
                        files_total=len(java_files),
                        files_done=files_done[0],
                        min_confidence=config.min_confidence,
                        partial=True,
                    )
                except OSError as snap_err:
                    logger.warning(
                        f"Failed to write partial snapshot: {snap_err}"
                    )

        result = await pipeline.collect_sinks(
            java_files,
            show_progress=sys.stderr.isatty(),
            on_file_done=_on_file_done if output else None,
        )

        dangerous = _filter_dangerous_sinks(result["sinks"], config.min_confidence)

        _display_sinks(result, dangerous, verbose)
        _display_cache_summary(pipeline)

        if output:
            _save_sinks(result, dangerous, config.min_confidence, output)
            click.echo(f"\n✓ Results saved to: {output}")

        sys.exit(0)

    except SystemExit:
        raise
    except Exception as e:
        logger.error(f"Sink inventory failed: {str(e)}")
        click.echo(f"\n✗ Error: {str(e)}", err=True)
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def _filter_dangerous_sinks(sinks: list, min_confidence: float) -> list:
    """Keep only dangerous sinks: sink_category != BENIGN and conf >= threshold.

    ``UNKNOWN`` (and a missing category) are *kept* on purpose — an unfamiliar
    API is a possible 0-day, so suppressing it would hurt recall. Only the
    explicitly-benign category is dropped.

    Args:
        sinks: List of ``(file_path, Sink)`` tuples from ``collect_sinks``.
        min_confidence: Minimum confidence to keep a sink.

    Returns:
        Filtered list of ``(file_path, Sink)`` tuples.
    """
    kept = []
    for file_path, sink in sinks:
        category = getattr(sink, "sink_category", None)
        if category == SinkCategory.BENIGN:
            continue
        if sink.confidence < min_confidence:
            continue
        kept.append((file_path, sink))
    return kept


def _display_results(result: dict, verbose: bool):
    """Display analysis results to console."""
    is_project = "files_analyzed" in result

    click.echo(f"\n{'='*70}")
    click.echo("RESULTS")
    click.echo(f"{'='*70}")

    metrics = result["metrics"]
    if is_project:
        click.echo(f"Files analyzed: {result['files_analyzed']}")
        if "files_llm_extracted" in result:
            click.echo(f"Files LLM-extracted: {result['files_llm_extracted']}")
            click.echo(f"Files skipped (no security patterns): {result['files_skipped']}")
    click.echo(f"Sources found: {metrics['sources_found']}")
    click.echo(f"Sinks found: {metrics['sinks_found']}")
    click.echo(f"Chains discovered: {metrics['chains_found']}")
    click.echo(f"Chains verified: {metrics['chains_verified']}")
    click.echo(f"Verification rate: {metrics['verification_rate']:.1%}")
    click.echo(f"Explanations generated: {metrics['explanations_generated']}")

    verified_chains = result["verified_chains"]

    if not verified_chains:
        click.echo("\n✓ No vulnerabilities found")
        return

    click.echo(f"\n{'='*70}")
    click.echo(f"VULNERABILITIES FOUND: {len(verified_chains)}")
    click.echo(f"{'='*70}")

    for i, chain in enumerate(verified_chains, 1):
        _display_chain(i, chain, result, verbose)

    click.echo(f"\n{'='*70}")


def _display_chain(index: int, chain, result: dict, verbose: bool):
    """Display a single vulnerability chain."""
    click.echo(f"\n[{index}] {chain.vulnerability_type.value}")

    src_file = getattr(chain.source.location, "file_path", "")
    sink_file = getattr(chain.sink.location, "file_path", "")
    if src_file and sink_file and src_file != sink_file:
        click.echo(f"  Source: {chain.source.variable_name} ({src_file}:{chain.source.location.line_number})")
        click.echo(f"  Sink: {chain.sink.variable_name} ({sink_file}:{chain.sink.location.line_number})")
    else:
        click.echo(f"  Source: {chain.source.variable_name} (line {chain.source.location.line_number})")
        click.echo(f"  Sink: {chain.sink.variable_name} (line {chain.sink.location.line_number})")

    click.echo(f"  Confidence: {chain.confidence:.1%}")

    if chain.verification_status:
        click.echo(f"  Verification: {chain.verification_status.value}")

    if verbose:
        click.echo(f"  Path length: {len(chain.path)}")
        click.echo(f"  Path: {' -> '.join(node.variable_name for node in chain.path)}")

        explanation = result["explanations"].get(chain.id)
        if explanation:
            click.echo("\n  Explanation:")
            click.echo(f"  Why vulnerable: {explanation.why_vulnerable}")
            click.echo(f"  How to fix: {explanation.how_to_fix}")
            click.echo(f"  Severity: {explanation.severity}")
            if explanation.cwe_id:
                click.echo(f"  CWE: {explanation.cwe_id}")


def _chain_to_dict(chain, explanations: dict) -> dict:
    """Convert a TaintChain to a JSON-serializable dict."""
    chain_data = {
        "id": chain.id,
        "type": chain.vulnerability_type.value,
        "source": {
            "variable": chain.source.variable_name,
            "file": chain.source.location.file_path,
            "line": chain.source.location.line_number,
            "confidence": chain.source.confidence,
        },
        "sink": {
            "variable": chain.sink.variable_name,
            "file": chain.sink.location.file_path,
            "line": chain.sink.location.line_number,
            "confidence": chain.sink.confidence,
        },
        "path": [node.variable_name for node in chain.path],
        "confidence": chain.confidence,
    }

    if chain.verification_status:
        chain_data["verification"] = chain.verification_status.value

    explanation = explanations.get(chain.id)
    if explanation:
        chain_data["explanation"] = {
            "why_vulnerable": explanation.why_vulnerable,
            "how_to_fix": explanation.how_to_fix,
            "example_fix": explanation.example_fix,
            "severity": explanation.severity,
            "cwe_id": explanation.cwe_id,
        }

    return chain_data


def _display_sinks(result: dict, dangerous: list, verbose: bool):
    """Display the dangerous-sink inventory grouped by file."""
    raw_count = len(result["sinks"])
    dangerous_count = len(dangerous)
    dropped = raw_count - dangerous_count

    click.echo(f"\n{'='*70}")
    click.echo("DANGEROUS SINKS (project-wide inventory)")
    click.echo(f"{'='*70}")
    click.echo(f"Files analyzed: {result['files_analyzed']}")
    if "files_llm_extracted" in result:
        click.echo(f"Files LLM-extracted: {result['files_llm_extracted']}")
        click.echo(f"Files skipped: {result['files_skipped']}")
    click.echo(f"Sinks found (raw): {raw_count}")
    click.echo(f"Dangerous sinks (after filter): {dangerous_count}")
    click.echo(f"Dropped (benign / below confidence): {dropped}")

    if not dangerous:
        click.echo("\n✓ No dangerous sinks found")
        return

    # Group by file, ordered by (file, line) for stable, scannable output.
    by_file: dict = {}
    for file_path, sink in dangerous:
        by_file.setdefault(file_path, []).append(sink)

    for file_path in sorted(by_file):
        file_sinks = sorted(by_file[file_path], key=lambda s: s.location.line_number)
        click.echo(f"\n[File: {file_path}]")
        for sink in file_sinks:
            category = getattr(sink, "sink_category", None)
            cat_str = category.value if category else "unknown"
            click.echo(
                f"  L{sink.location.line_number}  "
                f"{sink.vulnerability_type.value}  "
                f"{cat_str}  "
                f"var={sink.variable_name}  "
                f"conf={sink.confidence:.2f}"
            )
            if verbose:
                if sink.code_snippet:
                    click.echo(f"       code: {sink.code_snippet.strip()}")
                if sink.vulnerability_label:
                    click.echo(f"       label: {sink.vulnerability_label}")
                if sink.cwe_id:
                    click.echo(f"       cwe: {sink.cwe_id}")
                if sink.reasoning:
                    click.echo(f"       reasoning: {sink.reasoning}")

    click.echo(f"\n{'='*70}")


def _sink_to_dict(file_path: str, sink) -> dict:
    """Convert a Sink to a JSON-serializable dict for the inventory."""
    category = getattr(sink, "sink_category", None)
    return {
        "file": file_path,
        "line": sink.location.line_number,
        "variable": sink.variable_name,
        "type": sink.type,
        "vulnerability_type": sink.vulnerability_type.value,
        "vulnerability_label": sink.vulnerability_label,
        "cwe_id": sink.cwe_id,
        "sink_category": category.value if category else None,
        "confidence": sink.confidence,
        "code_snippet": sink.code_snippet,
        "reasoning": sink.reasoning,
    }


def _save_sinks(
    result: dict, dangerous: list, min_confidence: float, output_path: str
):
    """Save the final dangerous-sink inventory to a JSON file (atomic)."""
    output_data = {
        "analysis_mode": "sinks",
        "partial": False,
        "files_analyzed": result["files_analyzed"],
        "files_done": result["files_analyzed"],
        "filter": {
            "exclude_benign": True,
            "min_confidence": min_confidence,
        },
        "total_sinks_raw": len(result["sinks"]),
        "total_sinks_dangerous": len(dangerous),
        "sinks": [_sink_to_dict(file_path, sink) for file_path, sink in dangerous],
    }
    _atomic_write_json(output_path, output_data)


def _save_sinks_snapshot(
    output_path: str,
    collected_running: list,
    *,
    files_total: int,
    files_done: int,
    min_confidence: float,
    partial: bool,
):
    """Write a mid-run snapshot of the sink inventory atomically.

    Filtering matches ``_filter_dangerous_sinks`` so the on-disk file always
    reflects the same shape readers expect from the final output.
    """
    dangerous = _filter_dangerous_sinks(collected_running, min_confidence)
    snapshot = {
        "analysis_mode": "sinks",
        "partial": partial,
        "files_analyzed": files_total,
        "files_done": files_done,
        "filter": {
            "exclude_benign": True,
            "min_confidence": min_confidence,
        },
        "total_sinks_raw": len(collected_running),
        "total_sinks_dangerous": len(dangerous),
        "sinks": [_sink_to_dict(fp, s) for fp, s in dangerous],
    }
    _atomic_write_json(output_path, snapshot)


def _atomic_write_json(output_path: str, data: dict):
    """Write JSON via tmp + os.replace so readers never see a partial file."""
    tmp_path = f"{output_path}.tmp"
    with open(tmp_path, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp_path, output_path)


def _save_results(result: dict, output_path: str):
    """Save final analyze results to JSON file (atomic, partial=false)."""
    is_project = "files_analyzed" in result

    if is_project:
        output_data = {
            "analysis_mode": "project",
            "partial": False,
            "stage_completed": 4,
            "files_analyzed": result["files_analyzed"],
            "file_list": result.get("file_list", []),
            "total_chains": result["total_chains"],
            "metrics": result["metrics"],
            "vulnerabilities": [
                _chain_to_dict(chain, result["explanations"])
                for chain in result["verified_chains"]
            ],
        }
    else:
        output_data = {
            "file": result["file"],
            "partial": False,
            "stage_completed": 4,
            "total_chains": result["total_chains"],
            "metrics": result["metrics"],
            "vulnerabilities": [
                _chain_to_dict(chain, result["explanations"])
                for chain in result["verified_chains"]
            ],
        }

    _atomic_write_json(output_path, output_data)


def _source_to_dict(source) -> dict:
    """Convert a Source to a JSON-serializable dict for Stage 1 inventory."""
    category = getattr(source, "source_category", None)
    return {
        "file": source.location.file_path,
        "line": source.location.line_number,
        "variable": source.variable_name,
        "type": source.type,
        "source_category": category.value if category else None,
        "confidence": source.confidence,
        "code_snippet": source.code_snippet,
    }


def _save_results_stage1_snapshot(
    output_path: str, snapshot: dict, *, is_multi_file: bool
):
    """Write a Stage-1-boundary snapshot of analyze results (partial=true).

    Matches the final ``_save_results`` schema (so readers don't switch
    schemas mid-run): same keys, plus ``stage1_inventory`` with the raw
    extracted sources and sinks. ``vulnerabilities`` is empty until Stages
    2-4 run; on success the final write replaces this snapshot.
    """
    sources = snapshot["sources"]
    sinks = snapshot["sinks"]
    sanitizers = snapshot["sanitizers"]

    metrics = {
        "sources_found": len(sources),
        "sinks_found": len(sinks),
        "sanitizers_found": len(sanitizers),
        "chains_found": 0,
        "chains_verified": 0,
        "verification_rate": 0.0,
        "explanations_generated": 0,
        "graph_nodes": 0,
        "graph_edges": 0,
    }
    inventory = {
        "sources": [_source_to_dict(s) for s in sources],
        "sinks": [_sink_to_dict(s.location.file_path, s) for s in sinks],
    }

    if is_multi_file:
        data = {
            "analysis_mode": "project",
            "partial": True,
            "stage_completed": 1,
            "files_analyzed": snapshot["files_analyzed"],
            "file_list": snapshot["file_list"],
            "total_chains": 0,
            "metrics": metrics,
            "stage1_inventory": inventory,
            "vulnerabilities": [],
        }
    else:
        data = {
            "file": snapshot["file_list"][0],
            "partial": True,
            "stage_completed": 1,
            "total_chains": 0,
            "metrics": metrics,
            "stage1_inventory": inventory,
            "vulnerabilities": [],
        }
    _atomic_write_json(output_path, data)


if __name__ == "__main__":
    cli()
