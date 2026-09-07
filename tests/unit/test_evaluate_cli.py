"""Tests for the packaged ``vtc evaluate`` command."""

from unittest.mock import patch

from click.testing import CliRunner

from src.pipeline.main import cli


def test_evaluate_is_registered_on_primary_cli() -> None:
    result = CliRunner().invoke(cli, ["--help"])

    assert result.exit_code == 0
    assert "evaluate" in result.output


@patch("src.pipeline.main.run_evaluation_command", return_value=0)
def test_evaluate_forwards_all_projects_options(run_command) -> None:
    result = CliRunner().invoke(
        cli,
        [
            "evaluate",
            "--all-projects",
            "--backend",
            "static",
            "--phase-label",
            "static-honest",
            "--refresh-specs",
        ],
    )

    assert result.exit_code == 0
    run_command.assert_called_once_with(
        fixtures_dir=None,
        project=None,
        all_projects=True,
        save=None,
        report_md=None,
        baseline=False,
        phase_label="static-honest",
        diff_paths=None,
        refresh_specs=True,
        analysis_backend="static",
        llm_analysis_mode=None,
    )


@patch("src.pipeline.main.run_evaluation_command", return_value=0)
def test_evaluate_forwards_diff_paths(run_command, tmp_path) -> None:
    baseline = tmp_path / "baseline.json"
    candidate = tmp_path / "candidate.json"
    baseline.write_text("{}")
    candidate.write_text("{}")

    result = CliRunner().invoke(
        cli,
        ["evaluate", "--diff", str(baseline), str(candidate)],
    )

    assert result.exit_code == 0
    assert run_command.call_args.kwargs["diff_paths"] == (baseline, candidate)


def test_evaluate_rejects_conflicting_project_selection() -> None:
    result = CliRunner().invoke(
        cli,
        ["evaluate", "--all-projects", "--project", "example"],
    )

    assert result.exit_code == 2
    assert "exclusive" in result.output
