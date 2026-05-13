"""Progress reporting for pipeline stages."""

import sys
import time
from typing import Optional, TextIO


class ProgressReporter:
    """Renders a progress bar to stderr using carriage return overwrite.

    Example output::

        Stage 1: Extracting specs [=====>          ] 5/17 (29%, avg 2.1s/file, ETA ~25s)
    """

    BAR_WIDTH = 30

    def __init__(
        self,
        total: int,
        stage_name: str,
        stream: Optional[TextIO] = None,
    ) -> None:
        self.total = max(total, 1)
        self.stage_name = stage_name
        self.stream = stream or sys.stderr
        self.completed = 0
        self._start = time.monotonic()

    def update(self, n: int = 1) -> None:
        """Mark *n* items as completed and redraw the bar."""
        self.completed = min(self.completed + n, self.total)
        self._draw()

    def finish(self) -> None:
        """Fill the bar to 100 % and write a final newline."""
        self.completed = self.total
        self._draw()
        self.stream.write("\n")
        self.stream.flush()

    def _draw(self) -> None:
        elapsed = time.monotonic() - self._start
        pct = self.completed / self.total
        filled = int(self.BAR_WIDTH * pct)
        bar = "=" * filled
        if filled < self.BAR_WIDTH:
            bar += ">"
        bar = bar.ljust(self.BAR_WIDTH)

        avg = elapsed / self.completed if self.completed > 0 else 0
        remaining = self.total - self.completed
        eta = f", ETA ~{avg * remaining:.0f}s" if self.completed > 0 else ""

        line = (
            f"\r{self.stage_name} [{bar}] "
            f"{self.completed}/{self.total} "
            f"({pct:.0%}, avg {avg:.1f}s/file{eta})"
        )
        self.stream.write(line)
        self.stream.flush()
