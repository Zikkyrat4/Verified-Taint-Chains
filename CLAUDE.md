# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Development Commands

```bash
# Install dependencies (editable mode with dev dependencies)
pip install -e ".[dev]"

# Run all tests
pytest

# Run tests with coverage
pytest --cov=src

# Run a single test file
pytest tests/unit/test_example.py

# Run a specific test
pytest tests/unit/test_example.py::test_function_name

# Linting and formatting
ruff check src tests
black --check src tests
black src tests  # auto-format

# Type checking
mypy src

# Run the CLI
vtc --help
```

## Architecture

This is a 4-stage pipeline for security vulnerability analysis using LLM-assisted taint chain verification:

- **Stage 1 (LLM Inference)**: Identifies potential security-sensitive code patterns using LLMs
- **Stage 2 (Path Discovery)**: Discovers data flow paths between sources and sinks via static analysis
- **Stage 3 (Verification)**: Verifies discovered taint chains for actual exploitability
- **Stage 4 (Explanation)**: Generates human-readable vulnerability explanations

Key directories:
- `src/core/` - Pydantic models and shared types
- `src/pipeline/` - Orchestration logic connecting the stages
- `src/utils/` - Shared utilities (logging, config, file handling)
- `tests/` - Unit, integration, and performance tests
- `tests/fixtures/real_world/<project>/` - One subdirectory per real-world
  project used in the evaluation harness; each carries its own
  `ground_truth.json`. Currently covers 6 CWE classes across 6 projects
  (keycloak, spark, jenkins-docker-commons, jenkins-perfecto, jspwiki,
  cron-utils, spring-framework). Schema and CWE-coverage matrix:
  `tests/fixtures/real_world/README.md`. Adding a new project = new
  directory; no core changes needed.
- `scripts/evaluate.py` - Project-agnostic evaluation harness. Common modes:
  `--project <name>` (one project, output → `evaluation/<name>/`),
  `--all-projects` (walks all + aggregate table), `--fixtures-dir <path>`
  (back-compat / explicit). `--diff a.json b.json` for delta tables.
- `evaluation/<project>/` - Snapshot reports per project
  (`baseline.{json,md}`, `after.{json,md}`).
- `examples/` - Example code and usage demonstrations
- `docs/` - Comprehensive documentation

## Universality contract

The detector core (`src/`) MUST stay project-agnostic. Validate with
`grep -ri keycloak src/ --include="*.py"` — should return empty. Project
specifics live only under `tests/fixtures/real_world/<project>/`.

## Configuration

Environment variables are loaded from `.env` (copy from `.env.example`). Required:
- `OPENAI_API_KEY` - For LLM inference stages
- Or `LLM_PROVIDER=ollama` + `LLM_MODEL=...` + `OLLAMA_BASE_URL=...` for local Ollama
