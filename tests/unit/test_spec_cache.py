"""Tests for SpecCache — persistent content-addressed Stage 1 cache."""

import asyncio

from src.core.models import (
    CodeLocation,
    Sink,
    Source,
    Specification,
    VulnerabilityType,
)
from src.stage1_llm_inference.spec_cache import (
    CACHE_SCHEMA_VERSION,
    SpecCache,
    default_cache_dir,
)


def _make_spec(model: str = "gpt-4-turbo") -> Specification:
    return Specification(
        sources=[
            Source(
                location=CodeLocation(file_path="A.java", line_number=3),
                variable_name="user",
                type="HTTP",
                confidence=0.9,
                code_snippet='user = request.getParameter("u")',
            )
        ],
        sinks=[
            Sink(
                location=CodeLocation(file_path="A.java", line_number=10),
                variable_name="q",
                type="SQL",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                confidence=0.85,
                code_snippet="stmt.executeQuery(q)",
            )
        ],
        sanitizers=[],
        llm_model=model,
    )


def _kwargs(**overrides):
    base = {
        "llm_provider": "openai",
        "llm_model": "gpt-4-turbo",
        "min_confidence": 0.5,
    }
    base.update(overrides)
    return base


def test_put_then_get_round_trips(tmp_path):
    cache = SpecCache(cache_dir=tmp_path)
    spec = _make_spec()

    cache.put("source code", spec, **_kwargs())
    got = cache.get("source code", **_kwargs())

    assert got is not None
    assert got.sources[0].variable_name == "user"
    assert got.sinks[0].variable_name == "q"
    assert cache.stats.hits == 1
    assert cache.stats.misses == 0
    assert cache.stats.writes == 1


def test_get_miss_when_nothing_cached(tmp_path):
    cache = SpecCache(cache_dir=tmp_path)
    assert cache.get("anything", **_kwargs()) is None
    assert cache.stats.misses == 1
    assert cache.stats.hits == 0


def test_different_content_misses(tmp_path):
    cache = SpecCache(cache_dir=tmp_path)
    cache.put("code A", _make_spec(), **_kwargs())
    assert cache.get("code B", **_kwargs()) is None


def test_different_model_misses(tmp_path):
    """Model change = different cache key (a different model produces different
    results, replaying the wrong one would silently lose quality)."""
    cache = SpecCache(cache_dir=tmp_path)
    cache.put("code", _make_spec(), **_kwargs(llm_model="gpt-4"))
    assert cache.get("code", **_kwargs(llm_model="gpt-4-turbo")) is None


def test_different_provider_misses(tmp_path):
    """Same model name across providers (e.g. OpenAI vs proxy) must not collide."""
    cache = SpecCache(cache_dir=tmp_path)
    cache.put("code", _make_spec(), **_kwargs(llm_provider="openai"))
    assert cache.get("code", **_kwargs(llm_provider="ollama")) is None


def test_different_min_confidence_misses(tmp_path):
    cache = SpecCache(cache_dir=tmp_path)
    cache.put("code", _make_spec(), **_kwargs(min_confidence=0.5))
    assert cache.get("code", **_kwargs(min_confidence=0.7)) is None


def test_different_extractor_options_miss(tmp_path):
    cache = SpecCache(cache_dir=tmp_path)
    cache.put(
        "code", _make_spec(),
        **_kwargs(extractor_options="analysis_mode=targeted"),
    )

    assert cache.get(
        "code", **_kwargs(extractor_options="analysis_mode=exhaustive")
    ) is None


def test_corrupt_json_treated_as_miss(tmp_path):
    cache = SpecCache(cache_dir=tmp_path)
    key = SpecCache.compute_key("code", **_kwargs())
    path = tmp_path / "specs" / key[:2] / f"{key[2:]}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{ not valid json")

    # Must not raise; the broken file should be treated as a miss.
    got = cache.get("code", **_kwargs())
    assert got is None
    assert cache.stats.errors == 1


def test_disabled_cache_is_noop(tmp_path):
    cache = SpecCache(cache_dir=tmp_path, enabled=False)
    cache.put("code", _make_spec(), **_kwargs())
    # Nothing on disk, get always None.
    assert cache.get("code", **_kwargs()) is None
    assert cache.stats.writes == 0


def test_schema_version_mismatch_purges(tmp_path):
    """Bumping CACHE_SCHEMA_VERSION must clear the old specs dir at init."""
    # Pre-seed cache with a stale VERSION sentinel and a spec file.
    (tmp_path / "VERSION").write_text("0")
    stale_specs = tmp_path / "specs" / "aa"
    stale_specs.mkdir(parents=True)
    stale_file = stale_specs / "bb.json"
    stale_file.write_text("{}")

    SpecCache(cache_dir=tmp_path)  # init triggers purge + version write

    assert not stale_file.exists()
    assert (tmp_path / "VERSION").read_text().strip() == CACHE_SCHEMA_VERSION


def test_sharding_layout(tmp_path):
    """Cached entries land under specs/<hash[:2]>/<hash[2:]>.json."""
    cache = SpecCache(cache_dir=tmp_path)
    cache.put("code", _make_spec(), **_kwargs())
    key = SpecCache.compute_key("code", **_kwargs())
    expected = tmp_path / "specs" / key[:2] / f"{key[2:]}.json"
    assert expected.exists()
    # Round-trip JSON is a valid Specification.
    Specification.model_validate_json(expected.read_text())


def test_concurrent_writes_same_key_resolve_atomically(tmp_path):
    """Two coroutines racing the same key → one valid final file, no .tmp left."""
    cache = SpecCache(cache_dir=tmp_path)

    async def writer():
        cache.put("code", _make_spec(), **_kwargs())

    async def main():
        await asyncio.gather(writer(), writer(), writer())

    asyncio.run(main())

    key = SpecCache.compute_key("code", **_kwargs())
    path = tmp_path / "specs" / key[:2] / f"{key[2:]}.json"
    assert path.exists()
    assert not (path.parent / f"{path.name}.tmp").exists()
    # Result must be a valid Specification (atomic replace prevented torn writes).
    Specification.model_validate_json(path.read_text())


def test_default_cache_dir_for_directory(tmp_path):
    assert default_cache_dir(str(tmp_path)) == tmp_path / ".vtc-cache"


def test_default_cache_dir_for_file(tmp_path):
    f = tmp_path / "A.java"
    f.write_text("class A {}")
    # Single-file: cache sits next to it, not inside.
    assert default_cache_dir(str(f)) == tmp_path / ".vtc-cache"


def test_default_cache_dir_for_missing_file(tmp_path):
    f = tmp_path / "Missing.java"
    assert default_cache_dir(str(f)) == tmp_path / ".vtc-cache"


def test_summary_line_includes_stats(tmp_path):
    cache = SpecCache(cache_dir=tmp_path)
    cache.put("a", _make_spec(), **_kwargs())
    cache.get("a", **_kwargs())  # 1 hit
    cache.get("b", **_kwargs())  # 1 miss
    line = cache.summary_line()
    assert "1 hits" in line
    assert "1 misses" in line
    assert "1 writes" in line
