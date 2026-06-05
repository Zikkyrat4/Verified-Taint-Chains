"""Persistent content-addressed cache for Stage 1 specifications.

Massive Java projects (60k+ files) take days/weeks to fully extract because each
file triggers one or more LLM calls. A single restart (crash, OOM, network blip,
Ctrl-C) wipes all progress. This cache stores the extracted ``Specification``
keyed by SHA-256 of the file content plus every input that affects extraction:
extractor version, prompt template version, LLM provider/model, min confidence.

Any of those changing → cache miss → fresh LLM call. This guarantees that a
cached entry is an *exact replay* of a previous LLM run — never a stale result.

The cache is content-addressed (not path-addressed) so that moving or renaming
a file does not invalidate it, and that two paths with identical contents
share a single entry.

Layout (sharded to keep per-directory inode counts bounded):

    <cache_dir>/VERSION                          # cache_schema_version sentinel
    <cache_dir>/specs/<hash[:2]>/<hash[2:]>.json # one cached Specification
"""

from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

from src.core.models import Specification
from src.utils.logger import get_logger

logger = get_logger()


# Bump when the on-disk JSON format changes incompatibly. Cache dirs with a
# different VERSION sentinel are auto-purged on init.
CACHE_SCHEMA_VERSION = "1"

# Bump when the extractor pipeline changes in a way that would alter outputs
# (e.g. classification rules, JSP setter pass, snippet resolution). Independent
# from CACHE_SCHEMA_VERSION because old caches stay readable — they just don't
# match the new extractor's expected output.
EXTRACTOR_VERSION = "1"

# Bump when prompt templates change. Same rationale as EXTRACTOR_VERSION.
PROMPT_TEMPLATE_VERSION = "1"


@dataclass
class CacheStats:
    """Counters for cache effectiveness — surfaced in CLI summary."""

    hits: int = 0
    misses: int = 0
    writes: int = 0
    errors: int = 0

    def as_dict(self) -> Dict[str, int]:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "writes": self.writes,
            "errors": self.errors,
        }


@dataclass
class SpecCache:
    """Content-addressed persistent cache of Stage 1 ``Specification`` objects.

    A no-op when ``enabled=False``: every ``get`` is a miss, every ``put`` is a
    no-op. Lets callers wire the cache unconditionally and toggle via config.

    Thread-safety: callers run under a single asyncio event loop, so the only
    concurrency is between coroutines on the same thread. The atomic
    ``.tmp + os.replace`` write pattern handles two coroutines racing on the
    same key (file with identical content in two paths).
    """

    cache_dir: Path
    enabled: bool = True
    stats: CacheStats = field(default_factory=CacheStats)

    def __post_init__(self) -> None:
        if not self.enabled:
            return
        self.cache_dir = Path(self.cache_dir)
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logger.warning(
                f"Failed to create cache dir {self.cache_dir}: {e}. Disabling cache."
            )
            self.enabled = False
            return
        self._enforce_schema_version()
        (self.cache_dir / "specs").mkdir(exist_ok=True)
        logger.info(f"Spec cache enabled at {self.cache_dir}")

    def _enforce_schema_version(self) -> None:
        """If VERSION sentinel disagrees with current schema, purge specs dir."""
        version_file = self.cache_dir / "VERSION"
        if version_file.exists():
            try:
                current = version_file.read_text().strip()
            except OSError:
                current = ""
            if current == CACHE_SCHEMA_VERSION:
                return
            logger.info(
                f"Cache schema version mismatch ({current!r} vs "
                f"{CACHE_SCHEMA_VERSION!r}); purging {self.cache_dir / 'specs'}"
            )
            specs_dir = self.cache_dir / "specs"
            if specs_dir.exists():
                shutil.rmtree(specs_dir, ignore_errors=True)
        try:
            version_file.write_text(CACHE_SCHEMA_VERSION)
        except OSError as e:
            logger.warning(f"Failed to write cache VERSION file: {e}")

    # ------------------------------------------------------------------ key

    @staticmethod
    def compute_key(
        file_content: str,
        *,
        llm_provider: str,
        llm_model: str,
        min_confidence: float,
    ) -> str:
        """SHA-256 hex digest covering content + every extractor-affecting input.

        Any change in the inputs flips the key → cache miss. This is what makes
        a hit safe: same key implies same logical computation.
        """
        h = hashlib.sha256()
        # NUL bytes between fields prevent ambiguity between e.g.
        # ("a", "bc") and ("ab", "c") yielding the same digest.
        h.update(file_content.encode("utf-8"))
        h.update(b"\0")
        h.update(CACHE_SCHEMA_VERSION.encode("ascii"))
        h.update(b"\0")
        h.update(EXTRACTOR_VERSION.encode("ascii"))
        h.update(b"\0")
        h.update(PROMPT_TEMPLATE_VERSION.encode("ascii"))
        h.update(b"\0")
        h.update(llm_provider.encode("utf-8"))
        h.update(b"\0")
        h.update(llm_model.encode("utf-8"))
        h.update(b"\0")
        h.update(f"{min_confidence:.6f}".encode("ascii"))
        return h.hexdigest()

    def _path_for_key(self, key: str) -> Path:
        # Sharded so no single directory blows past sensible inode counts on
        # 60k+ entries. Two-char shard = 256 buckets, plenty for ~hundreds of
        # thousands of files.
        return self.cache_dir / "specs" / key[:2] / f"{key[2:]}.json"

    # ----------------------------------------------------------------- get

    def get(
        self,
        file_content: str,
        *,
        llm_provider: str,
        llm_model: str,
        min_confidence: float,
    ) -> Optional[Specification]:
        """Return a cached ``Specification`` or ``None`` on miss/error.

        Errors (missing file, corrupt JSON, schema drift) are treated as misses
        rather than raised: a broken entry must never block extraction.
        """
        if not self.enabled:
            return None
        key = self.compute_key(
            file_content,
            llm_provider=llm_provider,
            llm_model=llm_model,
            min_confidence=min_confidence,
        )
        path = self._path_for_key(key)
        if not path.exists():
            self.stats.misses += 1
            return None
        try:
            raw = path.read_text(encoding="utf-8")
            spec = Specification.model_validate_json(raw)
            self.stats.hits += 1
            return spec
        except (OSError, ValueError) as e:
            # Corrupt or unreadable: drop the entry, count as miss.
            self.stats.errors += 1
            self.stats.misses += 1
            logger.debug(f"Cache read failed for {path}: {e}; treating as miss")
            try:
                path.unlink()
            except OSError:
                pass
            return None

    # ----------------------------------------------------------------- put

    def put(
        self,
        file_content: str,
        spec: Specification,
        *,
        llm_provider: str,
        llm_model: str,
        min_confidence: float,
    ) -> None:
        """Persist a ``Specification`` for future ``get`` calls.

        Atomic via ``.tmp + os.replace`` so a concurrent reader never sees a
        half-written file, and two coroutines racing on the same key both
        produce a valid final file (whichever wins last is fine — same input
        ⇒ same output).
        """
        if not self.enabled:
            return
        key = self.compute_key(
            file_content,
            llm_provider=llm_provider,
            llm_model=llm_model,
            min_confidence=min_confidence,
        )
        path = self._path_for_key(key)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(spec.model_dump_json(), encoding="utf-8")
            os.replace(tmp, path)
            self.stats.writes += 1
        except OSError as e:
            self.stats.errors += 1
            logger.warning(f"Cache write failed for {path}: {e}")

    # ----------------------------------------------------------------- summary

    def summary_line(self) -> str:
        """Human-readable one-liner for the CLI summary block."""
        if not self.enabled:
            return "Cache: disabled"
        total = self.stats.hits + self.stats.misses
        rate = (self.stats.hits / total * 100.0) if total else 0.0
        return (
            f"Cache: {self.stats.hits} hits, {self.stats.misses} misses "
            f"({rate:.1f}% hit rate), {self.stats.writes} writes"
        )


def default_cache_dir(source_path: str) -> Path:
    """Default location: ``<source_path>/.vtc-cache`` (single file → its parent)."""
    p = Path(source_path)
    base = p.parent if p.is_file() else p
    return base / ".vtc-cache"
