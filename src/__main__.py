"""CLI interface for Verified Taint Chains analysis tool."""

import asyncio
import sys
from pathlib import Path
from typing import Optional

import click

from src import __version__
from src.core.config import load_config_from_env
from src.core.exceptions import TaintAnalysisError
from src.pipeline.orchestrator import SimplePipeline
from src.utils.logger import setup_logger, get_logger


@click.group()
def cli() -> None:
    """Verified Taint Chains - LLM-assisted security vulnerability analysis tool.

    This tool analyzes Java source code for security vulnerabilities using a
    4-stage pipeline:
    1. LLM-based specification extraction
    2. Graph-based path discovery
    3. CFG-based verification
    4. LLM-based explanation generation
    """
    pass


@cli.command()
@click.option(
    "--file",
    "-f",
    required=True,
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    help="Input Java source file to analyze.",
)
@click.option(
    "--output",
    "-o",
    default="results.json",
    type=click.Path(),
    help="Output JSON file for results (default: results.json).",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose output (DEBUG level logging).",
)
def analyze(file: str, output: str, verbose: bool) -> None:
    """Analyze Java source file for security vulnerabilities.

    Performs a complete 4-stage security analysis on the specified Java file
    and saves results to JSON output.

    Example usage:
      python -m src analyze --file app.java --output results.json --verbose
    """
    try:
        # Setup logging
        log_level = "DEBUG" if verbose else "INFO"
        setup_logger(level=log_level)
        logger = get_logger()

        logger.info(f"Verified Taint Chains v{__version__}")
        logger.info(f"Starting analysis of {file}...")

        if verbose:
            logger.info("Verbose mode enabled (DEBUG logging)")

        # Load configuration from environment
        try:
            logger.debug("Loading configuration from environment...")
            config = load_config_from_env()
            logger.debug(f"Configuration loaded: model={config.llm_model}")
        except ValueError as e:
            click.echo(f"❌ Configuration Error: {str(e)}", err=True)
            logger.error(f"Configuration error: {str(e)}")
            sys.exit(1)

        # Verify input file
        input_path = Path(file)
        if not input_path.exists():
            click.echo(f"❌ File not found: {file}", err=True)
            logger.error(f"File not found: {file}")
            sys.exit(1)

        if not input_path.is_file():
            click.echo(f"❌ Path is not a file: {file}", err=True)
            logger.error(f"Path is not a file: {file}")
            sys.exit(1)

        # Create pipeline
        try:
            logger.debug("Initializing pipeline...")
            pipeline = SimplePipeline(config)
            logger.debug("Pipeline initialized successfully")
        except Exception as e:
            click.echo(f"❌ Pipeline initialization failed: {str(e)}", err=True)
            logger.error(f"Pipeline initialization failed: {str(e)}")
            sys.exit(1)

        # Run analysis
        click.echo("\n🔍 Running security analysis...\n")
        logger.info("Starting pipeline execution...")

        try:
            # Run async pipeline
            results = asyncio.run(pipeline.run(file))
            logger.info("Pipeline execution completed successfully")

        except FileNotFoundError as e:
            click.echo(f"❌ Analysis failed: File not found", err=True)
            logger.error(f"File not found: {str(e)}")
            sys.exit(1)

        except TaintAnalysisError as e:
            click.echo(f"❌ Analysis failed: {str(e)}", err=True)
            logger.error(f"Analysis failed: {str(e)}")
            sys.exit(1)

        except Exception as e:
            click.echo(f"❌ Unexpected error: {str(e)}", err=True)
            logger.error(f"Unexpected error during analysis: {str(e)}")
            sys.exit(1)

        # Create result object
        try:
            pipeline_result = pipeline.create_result(results, file)
            logger.debug("PipelineResult object created")
        except Exception as e:
            click.echo(f"❌ Failed to create result object: {str(e)}", err=True)
            logger.error(f"Failed to create result object: {str(e)}")
            sys.exit(1)

        # Save results
        try:
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            pipeline_result.save(str(output_path))

            click.echo(f"✓ Results saved to {output}\n")
            logger.info(f"Results saved to {output}")

        except IOError as e:
            click.echo(f"❌ Failed to save results: {str(e)}", err=True)
            logger.error(f"Failed to save results: {str(e)}")
            sys.exit(1)

        # Print summary
        summary = pipeline_result.get_summary()
        click.echo(summary)

        # Print metrics table
        click.echo("\n📊 Analysis Metrics:")
        click.echo("─" * 50)

        metrics = pipeline_result.metrics
        for key, value in metrics.items():
            # Format metric names
            key_display = key.replace("_", " ").title()

            # Format values
            if isinstance(value, float):
                if key == "verification_rate":
                    value_display = f"{value:.1%}"
                else:
                    value_display = f"{value:.2f}"
            else:
                value_display = str(value)

            click.echo(f"  {key_display:.<40} {value_display:>8}")

        click.echo("─" * 50)

        # Success message
        if pipeline_result.total_chains > 0:
            verified = len(pipeline_result.verified_chains)
            total = pipeline_result.total_chains

            if verified > 0:
                click.echo(
                    f"\n⚠️  Found {verified} verified vulnerable chain(s) out of {total} total chains!"
                )
            else:
                click.echo(f"\n✓ Found {total} chain(s) but none verified as vulnerable.")
        else:
            click.echo("\n✓ No vulnerable chains detected!")

        logger.info("Analysis completed successfully")

    except click.Abort:
        click.echo("\n❌ Analysis cancelled by user", err=True)
        logger.warning("Analysis cancelled by user")
        sys.exit(130)

    except KeyboardInterrupt:
        click.echo("\n❌ Analysis interrupted by user", err=True)
        logger.warning("Analysis interrupted by user")
        sys.exit(130)


@cli.command()
def version() -> None:
    """Display tool version and information."""
    from src import __author__, __description__

    click.echo(f"Verified Taint Chains v{__version__}")
    click.echo(f"Author: {__author__}")
    click.echo(f"Description: {__description__}")


@cli.command()
def config() -> None:
    """Display current configuration."""
    logger = get_logger()

    try:
        config = load_config_from_env()

        click.echo("\n⚙️  Configuration Settings:")
        click.echo("─" * 50)
        click.echo(f"  LLM Model ........................ {config.llm_model}")
        click.echo(f"  Max Path Length ................. {config.max_path_length}")
        click.echo(f"  Min Confidence .................. {config.min_confidence}")
        click.echo(f"  Verification Enabled ........... {config.verification_enabled}")
        click.echo(f"  Symbolic Execution Enabled ..... {config.symbolic_execution_enabled}")
        click.echo("─" * 50)

        click.echo("\n💾 Configuration Source:")
        click.echo("  Configuration loaded from environment variables")
        click.echo("  Expected .env file location: .env in current directory")

        logger.info("Configuration displayed")

    except ValueError as e:
        click.echo(f"❌ Configuration Error: {str(e)}", err=True)
        logger.error(f"Configuration error: {str(e)}")
        sys.exit(1)


@cli.command()
def help_env() -> None:
    """Display environment variable configuration options."""
    click.echo("\n📝 Environment Variables Configuration:")
    click.echo("─" * 70)

    env_vars = [
        (
            "OPENAI_API_KEY",
            "OpenAI API key (required)",
            "Your OpenAI API key for LLM inference",
        ),
        (
            "OPENAI_MODEL",
            "LLM model name",
            "Default: gpt-4-turbo",
        ),
        (
            "MAX_PATH_LENGTH",
            "Maximum taint chain path length",
            "Default: 15",
        ),
        (
            "MIN_CONFIDENCE",
            "Minimum confidence threshold (0.0-1.0)",
            "Default: 0.5",
        ),
        (
            "VERIFICATION_ENABLED",
            "Enable chain verification (true/false)",
            "Default: true",
        ),
        (
            "SYMBOLIC_EXECUTION_ENABLED",
            "Enable symbolic execution (true/false)",
            "Default: false",
        ),
    ]

    for var_name, description, default_info in env_vars:
        click.echo(f"\n  {var_name}")
        click.echo(f"    Description: {description}")
        click.echo(f"    {default_info}")

    click.echo("\n─" * 70)
    click.echo("\n📄 Example .env file:")
    click.echo("""
OPENAI_API_KEY=sk-your-api-key-here
OPENAI_MODEL=gpt-4-turbo
MAX_PATH_LENGTH=15
MIN_CONFIDENCE=0.5
VERIFICATION_ENABLED=true
SYMBOLIC_EXECUTION_ENABLED=false
""")


def main() -> None:
    """Main entry point for CLI."""
    try:
        cli()
    except Exception as e:
        click.echo(f"❌ Fatal error: {str(e)}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
