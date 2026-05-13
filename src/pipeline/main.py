"""CLI-интерфейс VTC — анализ безопасности Java-кода."""

import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import click

from src.core.config import load_config_from_env
from src.pipeline.orchestrator import SimplePipeline
from src.utils.logger import enable_stderr, get_logger

logger = get_logger()


def _find_java_files(path: str) -> List[str]:
    """Find all .java files in directory recursively, or return single file."""
    p = Path(path)
    if p.is_file():
        return [str(p)]
    return sorted(str(f) for f in p.rglob("*.java"))


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
    Логи: stderr (INFO) + vtc.log (DEBUG, полный лог)

    \b
    Примеры:
      vtc analyze code.java
      vtc analyze src/main/java/ -o report.json -v
      vtc analyze code.java --llm-provider ollama
    """
    pass


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
    "--verbose",
    "-v",
    is_flag=True,
    help="Подробный вывод: пути, объяснения, CWE.",
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
    verbose: bool,
):
    """Анализ Java-файла или директории на уязвимости.

    \b
    Логи автоматически пишутся в vtc.log (DEBUG) и stderr (INFO).

    \b
    Примеры:
      vtc analyze code.java
      vtc analyze code.java -o results.json -v
      vtc analyze src/main/java/ -o report.json
      vtc analyze code.java --llm-provider ollama --llm-model llama3.2:latest
      vtc analyze code.java --verification-level both --pathfinding-algorithm bfs
      vtc analyze src/ --max-files 50 --max-concurrent 2
    """
    # Enable terminal output only for the analyze command
    enable_stderr()

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

        # Find Java files
        java_files = _find_java_files(source_path)
        if not java_files:
            click.echo("No .java files found.")
            sys.exit(1)

        is_multi_file = len(java_files) > 1

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
        click.echo(f"Source: {source_path}")
        if is_multi_file:
            click.echo(f"Files to analyze: {len(java_files)}")
        click.echo(f"{'='*70}\n")

        # Create pipeline (reused for all files)
        pipeline = SimplePipeline(config)

        if is_multi_file:
            # Project mode: unified cross-file analysis
            result = await pipeline.run_project(
                java_files,
                show_progress=sys.stderr.isatty(),
            )
        else:
            # Single-file mode
            result = await pipeline.run(java_files[0])

        _display_results(result, verbose)

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
        click.echo(f"\n✓ No vulnerabilities found")
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
            click.echo(f"\n  Explanation:")
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


def _save_results(result: dict, output_path: str):
    """Save results to JSON file."""
    is_project = "files_analyzed" in result

    if is_project:
        output_data = {
            "analysis_mode": "project",
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
            "total_chains": result["total_chains"],
            "metrics": result["metrics"],
            "vulnerabilities": [
                _chain_to_dict(chain, result["explanations"])
                for chain in result["verified_chains"]
            ],
        }

    # Write to file
    with open(output_path, "w") as f:
        json.dump(output_data, f, indent=2)


if __name__ == "__main__":
    cli()
