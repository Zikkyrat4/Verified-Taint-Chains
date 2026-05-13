"""Tests for ProgressReporter."""

import io

from src.utils.progress import ProgressReporter


class TestProgressReporter:
    def test_update_increments_completed(self):
        stream = io.StringIO()
        pr = ProgressReporter(5, "Stage 1", stream=stream)
        pr.update()
        assert pr.completed == 1
        pr.update(2)
        assert pr.completed == 3

    def test_finish_fills_to_total(self):
        stream = io.StringIO()
        pr = ProgressReporter(10, "Test", stream=stream)
        pr.update(3)
        pr.finish()
        assert pr.completed == 10
        output = stream.getvalue()
        assert "100%" in output
        # finish writes a trailing newline
        assert output.endswith("\n")

    def test_does_not_exceed_total(self):
        stream = io.StringIO()
        pr = ProgressReporter(2, "Test", stream=stream)
        pr.update(5)
        assert pr.completed == 2

    def test_output_contains_stage_name(self):
        stream = io.StringIO()
        pr = ProgressReporter(3, "Stage 1: Extracting specs", stream=stream)
        pr.update()
        output = stream.getvalue()
        assert "Stage 1: Extracting specs" in output

    def test_bar_renders_progress(self):
        stream = io.StringIO()
        pr = ProgressReporter(2, "S", stream=stream)
        pr.update()
        output = stream.getvalue()
        assert "1/2" in output
        assert "50%" in output
