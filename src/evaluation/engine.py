"""Evaluation harness for VTC on real-world Java fixtures.

Runs SimplePipeline on each fixture file in a project directory, matches
reported chains against that project's ``ground_truth.json``, and computes
precision/recall/F1 plus a per-file breakdown of TP/FP/FN/unclassified.

Project-agnostic: each subdirectory under ``tests/fixtures/real_world/`` is a
project (one ``ground_truth.json`` + a tree of ``.java`` fixtures). The schema
is documented in ``tests/fixtures/real_world/README.md``.

Note on 0-day candidates: chains classified as ``unclassified`` are not
matched against any TP or known FP, so they remain useful for manual review.
They are nevertheless counted as false positives in the primary precision.

Usage:
    vtc evaluate --fixtures-dir tests/fixtures/real_world/<project> \\
        [--save evaluation.json] [--report-md OUT.md] [--baseline]
    vtc evaluate --diff baseline.json after.json
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[2]

from src.core.config import load_config_from_env  # noqa: E402
from src.pipeline.orchestrator import SimplePipeline  # noqa: E402

REAL_WORLD_DIR = ROOT / "tests" / "fixtures" / "real_world"
EVALUATION_DIR = ROOT / "evaluation"
DEFAULT_FIXTURES_DIR = REAL_WORLD_DIR / "keycloak"


def _list_projects() -> List[str]:
    """Return sorted names of project subdirs that have a ground_truth.json."""
    if not REAL_WORLD_DIR.exists():
        return []
    return sorted(
        p.name
        for p in REAL_WORLD_DIR.iterdir()
        if p.is_dir() and (p / "ground_truth.json").exists()
    )


# ---------------------------------------------------------------------------
# Matching helpers
# ---------------------------------------------------------------------------


def _norm(s: Optional[str]) -> str:
    return (s or "").strip().lower()


def _vars_match(reported: str, expected: str) -> bool:
    """Match Java identifiers without unsafe substring equivalence."""
    r, e = _canonical_var(reported), _canonical_var(expected)
    if not r or not e:
        return False
    return r == e


def _canonical_var(value: str) -> str:
    """Normalize a reported graph/display identifier to a Java symbol."""
    text = _norm(value).split(":")[-1]
    text = re.sub(r"^this\.", "", text)
    match = re.fullmatch(r"[a-z_$][a-z0-9_$]*", text)
    return match.group(0) if match else text


def _line_close(reported: int, expected: int, tolerance: int = 5) -> bool:
    """Lines match within tolerance; only an unknown expected line is unconstrained."""
    if expected == 0:
        return True
    if reported <= 0:
        return False
    return abs(reported - expected) <= tolerance


def _file_matches(reported_path: str, expected_basename: str) -> bool:
    """Project-mode file constraint: chain.source/sink.file ends with expected basename.

    The reported path may be absolute (e.g. ``/abs/project/src/Foo.java``);
    the TP encodes only a basename or short relative path (``Foo.java`` or
    ``pathtraversal/Foo.java``). Match by suffix.
    """
    if not expected_basename:
        return True  # no constraint declared
    r = _norm(reported_path)
    e = _norm(expected_basename)
    return r == e or r.endswith("/" + e)


def _chain_matches_tp(chain: Dict[str, Any], tp: Dict[str, Any]) -> bool:
    """Match a reported chain against an expected true positive.

    A TP requires exact canonical endpoint identifiers, exact vulnerability
    type, file suffixes when declared, and locations within the fixed five-line
    tolerance. Path intermediates and model-supplied CWE labels cannot replace
    an incorrect endpoint or type.
    """
    src_var = chain["source"]["variable"]
    sink_var = chain["sink"]["variable"]
    src_line = chain["source"].get("line", 0)
    sink_line = chain["sink"].get("line", 0)
    src_file = chain["source"].get("file", "") or ""
    sink_file = chain["sink"].get("file", "") or ""
    vuln_type = _norm(chain.get("type", ""))

    exp_src = tp.get("source_var", "")
    exp_sink = tp.get("sink_var", "")
    exp_src_file = tp.get("source_file", "")
    exp_sink_file = tp.get("sink_file", "")
    exp_type = _norm(tp.get("vuln_type", ""))

    # Project-mode file pinning: cross-file flow only credited when both
    # endpoints live in the declared files.
    if not (_file_matches(src_file, exp_src_file) and _file_matches(sink_file, exp_sink_file)):
        return False

    src_ok = _vars_match(src_var, exp_src)
    sink_ok = _vars_match(sink_var, exp_sink)
    var_ok = src_ok and sink_ok
    type_ok = not exp_type or vuln_type == exp_type
    line_ok = _line_close(src_line, tp.get("source_line", 0)) and _line_close(
        sink_line, tp.get("sink_line", 0)
    )
    return var_ok and type_ok and line_ok


def _tp_match_score(chain: Dict[str, Any], tp: Dict[str, Any]) -> Optional[int]:
    """Return a deterministic match score, preferring the closest locations."""
    if not _chain_matches_tp(chain, tp):
        return None
    score = 100
    for endpoint, key in (("source", "source_line"), ("sink", "sink_line")):
        reported = chain[endpoint].get("line", 0)
        expected = tp.get(key, 0)
        if reported and expected:
            score -= abs(reported - expected)
    if _vars_match(chain["sink"]["variable"], tp.get("sink_var", "")):
        score += 10
    return score


def _chain_matches_fp_pattern(chain: Dict[str, Any], fp: Dict[str, Any]) -> bool:
    """Check if a chain matches a false-positive pattern entry."""
    src_var = chain["source"]["variable"]
    sink_var = chain["sink"]["variable"]
    # Reach into snippet too if available (some patterns target sink_pattern in code)
    src_snip = chain["source"].get("code_snippet", "") or ""
    sink_snip = chain["sink"].get("code_snippet", "") or ""

    checks: List[bool] = []
    if "source_var" in fp:
        checks.append(_vars_match(src_var, fp["source_var"]))
    if "sink_var" in fp:
        checks.append(_vars_match(sink_var, fp["sink_var"]))
    if "source_pattern" in fp:
        checks.append(bool(re.search(fp["source_pattern"], f"{src_var} {src_snip}")))
    if "sink_pattern" in fp:
        checks.append(bool(re.search(fp["sink_pattern"], f"{sink_var} {sink_snip}")))
    return bool(checks) and all(checks)


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass
class FileEvaluation:
    file: str
    cve: str = ""
    expected_tp: int = 0
    found_tp: int = 0
    fp: int = 0
    unclassified: int = 0
    fn: int = 0
    tp_matched: List[Dict[str, Any]] = field(default_factory=list)
    fp_chains: List[Dict[str, Any]] = field(default_factory=list)
    fn_chains: List[Dict[str, Any]] = field(default_factory=list)
    unclassified_chains: List[Dict[str, Any]] = field(default_factory=list)
    pipeline_metrics: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class EvaluationReport:
    files: List[FileEvaluation] = field(default_factory=list)
    aggregate: Dict[str, Any] = field(default_factory=dict)
    analysis: Dict[str, Any] = field(default_factory=dict)


def _analysis_metadata(config: Any) -> Dict[str, Any]:
    """Capture every material analysis knob without exposing credentials."""
    uses_llm = config.analysis_backend != "static"
    effective_thinking = config.openai_thinking
    if uses_llm and effective_thinking is None and config.llm_model.lower().startswith("glm-"):
        effective_thinking = "disabled"
    return {
        "backend": config.analysis_backend,
        "llm_analysis_mode": config.llm_analysis_mode if uses_llm else "n/a",
        "llm_provider": config.llm_provider if uses_llm else "n/a",
        "llm_model": config.llm_model if uses_llm else "n/a",
        "min_confidence": config.min_confidence,
        "max_path_length": config.max_path_length,
        "pathfinding_algorithm": config.pathfinding_algorithm,
        "verification_enabled": config.verification_enabled,
        "verification_level": config.verification_level,
        "symbolic_execution_enabled": config.symbolic_execution_enabled,
        "use_joern": config.use_joern,
        "use_semantic_heuristic": config.use_semantic_heuristic,
        "use_astar": config.use_astar,
        "use_llm_graph_builder": config.use_llm_graph_builder,
        "llm_graph_enrichment_enabled": config.llm_graph_enrichment_enabled,
        "llm_graph_enrichment_confidence": config.llm_graph_enrichment_confidence,
        "llm_batch_max_chars": config.llm_batch_max_chars,
        "max_concurrent_files": config.max_concurrent_files,
        "max_concurrent_functions": config.max_concurrent_functions,
        "max_files": config.max_files,
        "cache_enabled": config.cache_enabled,
        "cache_read_enabled": config.cache_read_enabled,
        "openai_timeout": config.openai_timeout if uses_llm else "n/a",
        "llm_max_retries": config.llm_max_retries if uses_llm else "n/a",
        "llm_max_tokens": config.llm_max_tokens if uses_llm else "n/a",
        "openai_json_mode": config.openai_json_mode if uses_llm else "n/a",
        "openai_thinking": effective_thinking if uses_llm else "n/a",
        "evaluation_policy": {
            "all_labelled_true_positives": True,
            "exact_endpoint_identifiers": True,
            "exact_vulnerability_type": True,
            "line_tolerance": 5,
            "unmatched_findings_count_as_fp": True,
            "one_to_one_matching": True,
        },
    }


# ---------------------------------------------------------------------------
# Pipeline result -> chain dicts (stable schema for matching)
# ---------------------------------------------------------------------------


def _chain_to_dict(chain) -> Dict[str, Any]:
    return {
        "id": chain.id,
        "type": chain.vulnerability_type.value,
        "cwe": getattr(chain.sink, "cwe_id", None) or "",
        "vulnerability_label": getattr(chain.sink, "vulnerability_label", None) or "",
        "source": {
            "variable": chain.source.variable_name,
            "file": getattr(chain.source.location, "file_path", ""),
            "line": getattr(chain.source.location, "line_number", 0),
            "code_snippet": getattr(chain.source, "code_snippet", "") or "",
        },
        "sink": {
            "variable": chain.sink.variable_name,
            "file": getattr(chain.sink.location, "file_path", ""),
            "line": getattr(chain.sink.location, "line_number", 0),
            "code_snippet": getattr(chain.sink, "code_snippet", "") or "",
        },
        "path": [n.variable_name for n in chain.path],
        "confidence": chain.confidence,
    }


# ---------------------------------------------------------------------------
# Matching driver
# ---------------------------------------------------------------------------


def _classify_chains(
    chains: List[Dict[str, Any]],
    truth: Dict[str, Any],
    truth_file: str = "",
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Classify reported chains against ground truth.

    Returns (tp_matched, fp, unclassified, fn).
    """
    # Every labelled positive participates in the primary benchmark. Metadata
    # such as ``expected_realistic`` may describe difficulty, but must not
    # silently remove examples from recall.
    tps = list(truth.get("true_positives", []))
    fp_patterns = truth.get("false_positive_patterns", [])
    tp_matched: List[Dict[str, Any]] = []
    fp_chains: List[Dict[str, Any]] = []
    unclassified: List[Dict[str, Any]] = []
    matched_tp_ids = set()

    for chain in chains:
        # 1. Try matching against true positives first
        candidates = [
            (score, tp)
            for tp in tps
            if tp.get("id") not in matched_tp_ids
            if (score := _tp_match_score(chain, tp)) is not None
        ]
        matched_tp = max(candidates, key=lambda item: item[0])[1] if candidates else None

        if matched_tp is not None:
            tp_matched.append({"chain": chain, "tp": matched_tp})
            matched_tp_ids.add(matched_tp["id"])
            continue

        # 2. Try false-positive patterns
        fp_match = next(
            (
                fp
                for fp in fp_patterns
                if _chain_matches_fp_pattern(chain, fp)
                if not (
                    truth_file
                    and any(key.startswith("source_") for key in fp)
                    and not _file_matches(
                        chain["source"].get("file", ""),
                        fp.get("source_file", truth_file),
                    )
                )
            ),
            None,
        )
        if fp_match is not None:
            fp_chains.append({"chain": chain, "fp_pattern": fp_match})
            continue

        # 3. Neither expected TP nor a known-FP pattern. Kept separately for
        # triage, but included in the primary precision denominator.
        unclassified.append({"chain": chain})

    # Compute FNs from the complete labelled-positive set used for matching.
    fn_chains: List[Dict[str, Any]] = []
    for tp in tps:
        if tp.get("id") in matched_tp_ids:
            continue
        fn_chains.append(tp)

    return tp_matched, fp_chains, unclassified, fn_chains


# ---------------------------------------------------------------------------
# Aggregate metrics
# ---------------------------------------------------------------------------


def _aggregate(report: EvaluationReport) -> Dict[str, Any]:
    total_tp = sum(f.found_tp for f in report.files)
    total_fp = sum(f.fp for f in report.files)
    total_fn = sum(f.fn for f in report.files)
    total_uncl = sum(f.unclassified for f in report.files)
    expected_tp = sum(f.expected_tp for f in report.files)

    denom_known = total_tp + total_fp
    precision_known = total_tp / denom_known if denom_known else 0.0

    denom_all = total_tp + total_fp + total_uncl
    precision = total_tp / denom_all if denom_all else 0.0

    denom_r = total_tp + total_fn
    recall = total_tp / denom_r if denom_r else 0.0

    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "total_tp": total_tp,
        "total_fp": total_fp,
        "total_fn": total_fn,
        "total_unclassified": total_uncl,
        "expected_tp": expected_tp,
        "precision": round(precision, 4),
        "precision_known": round(precision_known, 4),
        "precision_lower_bound": round(precision, 4),
        "precision_strict": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "f1_lower_bound": round(f1, 4),
        "files_analyzed": len(report.files),
        "files_failed": sum(1 for f in report.files if f.error),
    }


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------


def _render_md(report: EvaluationReport) -> str:
    lines: List[str] = []
    agg = report.aggregate
    lines.append("# VTC Evaluation Report")
    lines.append("")
    lines.append("## Analysis configuration")
    lines.append("")
    lines.append(f"- Backend: `{report.analysis.get('backend', 'unknown')}`")
    lines.append(f"- LLM analysis mode: `{report.analysis.get('llm_analysis_mode', 'n/a')}`")
    lines.append(f"- Provider: `{report.analysis.get('llm_provider', 'n/a')}`")
    lines.append(f"- Model: `{report.analysis.get('llm_model', 'n/a')}`")
    lines.append(f"- Minimum confidence: `{report.analysis.get('min_confidence', 'unknown')}`")
    lines.append(f"- Verification: `{report.analysis.get('verification_level', 'unknown')}`")
    lines.append(f"- Pathfinder: `{report.analysis.get('pathfinding_algorithm', 'unknown')}`")
    lines.append(f"- Joern: `{report.analysis.get('use_joern', 'unknown')}`")
    lines.append(f"- LLM graph enrichment: `{report.analysis.get('llm_graph_enrichment_enabled', 'unknown')}`")
    lines.append(f"- Stage 1 cache reads: `{report.analysis.get('cache_read_enabled', 'unknown')}`")
    lines.append("")
    lines.append("## Aggregate metrics")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Files analyzed | {agg['files_analyzed']} |")
    lines.append(f"| Files failed | {agg['files_failed']} |")
    lines.append(f"| True positives | {agg['total_tp']} / {agg['expected_tp']} expected |")
    lines.append(f"| Known false positives | {agg['total_fp']} |")
    lines.append(f"| False negatives | {agg['total_fn']} |")
    lines.append(f"| Other unmatched findings | {agg['total_unclassified']} |")
    lines.append(f"| Precision (all unmatched findings are FP) | {agg['precision']:.2%} |")
    lines.append(f"| Precision on known labels only (diagnostic) | {agg['precision_known']:.2%} |")
    lines.append(f"| Recall | {agg['recall']:.2%} |")
    lines.append(f"| F1 | {agg['f1']:.4f} |")
    lines.append("")
    lines.append("## Per-file breakdown")
    lines.append("")

    for f in report.files:
        lines.append(f"### {f.file}")
        if f.cve:
            lines.append(f"_CVE:_ {f.cve}")
        lines.append("")
        if f.error:
            lines.append(f"**ERROR:** {f.error}")
            lines.append("")
            continue
        lines.append(f"- TP: {f.found_tp} / {f.expected_tp}")
        lines.append(f"- FP (matched patterns): {f.fp}")
        lines.append(f"- FN: {f.fn}")
        lines.append(f"- Unclassified: {f.unclassified}")
        lines.append(f"- Pipeline metrics: {f.pipeline_metrics}")
        lines.append("")
        if f.tp_matched:
            lines.append("#### True Positives matched")
            for entry in f.tp_matched:
                ch = entry["chain"]
                tp = entry["tp"]
                lines.append(
                    f"- `{ch['source']['variable']}` (line {ch['source']['line']}) -> "
                    f"`{ch['sink']['variable']}` (line {ch['sink']['line']}) "
                    f"[type={ch['type']}, conf={ch['confidence']:.2f}] "
                    f"== expected {tp.get('id')} ({tp.get('description', '')})"
                )
            lines.append("")
        if f.fp_chains:
            lines.append("#### False Positives (matched FP patterns)")
            for entry in f.fp_chains:
                ch = entry["chain"]
                fp = entry["fp_pattern"]
                lines.append(
                    f"- `{ch['source']['variable']}` -> `{ch['sink']['variable']}` "
                    f"[type={ch['type']}, conf={ch['confidence']:.2f}] — {fp.get('reason', '')}"
                )
            lines.append("")
        if f.fn_chains:
            lines.append("#### False Negatives (expected TPs not found)")
            for tp in f.fn_chains:
                lines.append(
                    f"- {tp.get('id')}: `{tp.get('source_var')}` -> `{tp.get('sink_var')}` "
                    f"({tp.get('description', '')})"
                )
            lines.append("")
        if f.unclassified_chains:
            lines.append("#### Unclassified chains")
            for entry in f.unclassified_chains:
                ch = entry["chain"]
                lines.append(
                    f"- `{ch['source']['variable']}` (line {ch['source']['line']}) -> "
                    f"`{ch['sink']['variable']}` (line {ch['sink']['line']}) "
                    f"[type={ch['type']}, conf={ch['confidence']:.2f}]"
                )
            lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main async evaluation
# ---------------------------------------------------------------------------


async def _evaluate_file(
    pipeline: SimplePipeline,
    file_path: Path,
    truth_for_file: Dict[str, Any],
) -> FileEvaluation:
    rel = str(file_path)
    fe = FileEvaluation(
        file=rel,
        cve=truth_for_file.get("cve", ""),
        expected_tp=len(truth_for_file.get("true_positives", [])),
    )
    try:
        result = await pipeline.run(str(file_path))
        fe.pipeline_metrics = result.get("metrics", {})
        chains = [_chain_to_dict(c) for c in result.get("verified_chains", [])]
        tp_matched, fp_chains, unclassified, fn_chains = _classify_chains(chains, truth_for_file)
        fe.tp_matched = tp_matched
        fe.fp_chains = fp_chains
        fe.unclassified_chains = unclassified
        fe.fn_chains = fn_chains
        fe.found_tp = len(tp_matched)
        fe.fp = len(fp_chains)
        fe.unclassified = len(unclassified)
        fe.fn = len(fn_chains)
    except Exception as exc:
        fe.error = f"{type(exc).__name__}: {exc}"
        fe.fn = fe.expected_tp
        fe.fn_chains = list(truth_for_file.get("true_positives", []))
    return fe


def _route_chain_to_file(
    chain: Dict[str, Any],
    file_keys: List[str],
) -> Optional[str]:
    """Attribute a project-mode chain to a ground-truth file key.

    A chain belongs to the file whose sink lives in it (that's where the
    vulnerability surfaces). Falls back to the source file if the sink path
    doesn't match any known key. Returns the most-specific (longest) match.
    """
    sink_path = _norm(chain["sink"].get("file", "") or "")
    src_path = _norm(chain["source"].get("file", "") or "")
    best: Optional[str] = None
    best_len = 0
    for key in file_keys:
        k = _norm(key)
        if not k:
            continue
        if _file_matches(sink_path, k):
            if len(k) > best_len:
                best, best_len = key, len(k)
    if best is not None:
        return best
    for key in file_keys:
        k = _norm(key)
        if not k:
            continue
        if _file_matches(src_path, k):
            if len(k) > best_len:
                best, best_len = key, len(k)
    return best


async def _run_project_evaluation(
    fixtures_dir: Path,
    truth: Dict[str, Any],
    refresh_specs: bool = False,
    analysis_backend: Optional[str] = None,
    llm_analysis_mode: Optional[str] = None,
) -> EvaluationReport:
    """Evaluate a multi-file fixture using pipeline.run_project once.

    The whole .java tree under fixtures_dir is handed to the project-mode
    orchestrator so cross-file taint flows are visible. Reported chains are
    then routed back to the per-file rows of ground_truth.json via
    ``_route_chain_to_file``.
    """
    config = load_config_from_env(
        analysis_backend_override=analysis_backend,
        llm_analysis_mode_override=llm_analysis_mode,
    )
    config.cache_read_enabled = not refresh_specs
    config.cache_dir = str(EVALUATION_DIR / ".vtc-cache" / fixtures_dir.name)
    pipeline = SimplePipeline(config)
    report = EvaluationReport(analysis=_analysis_metadata(config))

    java_files = sorted(str(p) for p in fixtures_dir.rglob("*.java"))
    if not java_files:
        print(f"[skip] no .java files under {fixtures_dir}", file=sys.stderr)
        report.aggregate = _aggregate(report)
        await pipeline.aclose()
        return report

    print(
        f"[run] project mode: {len(java_files)} files under {fixtures_dir.name}",
        file=sys.stderr,
    )

    # Pre-initialise one FileEvaluation per ground-truth file so absent
    # findings still show as FN rows.
    file_evals: Dict[str, FileEvaluation] = {}
    for rel_name, truth_for_file in truth.get("files", {}).items():
        expected = len(truth_for_file.get("true_positives", []))
        file_evals[rel_name] = FileEvaluation(
            file=rel_name,
            cve=truth_for_file.get("cve", ""),
            expected_tp=expected,
        )

    try:
        result = await pipeline.run_project(java_files, show_progress=False)
    except Exception as exc:
        # Attach error to every file entry so the report shows it.
        msg = f"{type(exc).__name__}: {exc}"
        for fe in file_evals.values():
            fe.error = msg
            fe.fn = fe.expected_tp
            fe.fn_chains = list(
                truth.get("files", {}).get(fe.file, {}).get("true_positives", [])
            )
        report.files = list(file_evals.values())
        report.aggregate = _aggregate(report)
        await pipeline.aclose()
        return report

    pipeline_metrics = result.get("metrics", {})
    chains = [_chain_to_dict(c) for c in result.get("verified_chains", [])]
    file_keys = list(truth.get("files", {}).keys())

    # Bucket chains by attributed ground-truth file.
    buckets: Dict[str, List[Dict[str, Any]]] = {k: [] for k in file_keys}
    orphan_chains: List[Dict[str, Any]] = []
    for ch in chains:
        key = _route_chain_to_file(ch, file_keys)
        if key is None:
            orphan_chains.append(ch)
        else:
            buckets[key].append(ch)

    for rel_name, truth_for_file in truth.get("files", {}).items():
        fe = file_evals[rel_name]
        fe.pipeline_metrics = pipeline_metrics
        tp_matched, fp_chains, unclassified, fn_chains = _classify_chains(
            buckets[rel_name], truth_for_file, truth_file=rel_name
        )
        fe.tp_matched = tp_matched
        fe.fp_chains = fp_chains
        fe.unclassified_chains = unclassified
        fe.fn_chains = fn_chains
        fe.found_tp = len(tp_matched)
        fe.fp = len(fp_chains)
        fe.unclassified = len(unclassified)
        fe.fn = len(fn_chains)

    # Chains whose sink/source file didn't map to any ground-truth key go into
    # a synthetic bucket. They remain visible and count against precision.
    if orphan_chains:
        orphan = FileEvaluation(file="<project-orphan>")
        orphan.unclassified_chains = [{"chain": c} for c in orphan_chains]
        orphan.unclassified = len(orphan_chains)
        orphan.pipeline_metrics = pipeline_metrics
        report.files = list(file_evals.values()) + [orphan]
    else:
        report.files = list(file_evals.values())

    report.aggregate = _aggregate(report)
    await pipeline.aclose()
    return report


async def _run_evaluation(
    fixtures_dir: Path,
    truth: Dict[str, Any],
    refresh_specs: bool = False,
    analysis_backend: Optional[str] = None,
    llm_analysis_mode: Optional[str] = None,
) -> EvaluationReport:
    # Project-mode fixture: hand the entire .java tree to pipeline.run_project
    # so cross-file flows (e.g. subclass entry point → inherited base method)
    # can actually be traced. Single-file mode is the default.
    if truth.get("mode") == "project":
        return await _run_project_evaluation(
            fixtures_dir,
            truth,
            refresh_specs,
            analysis_backend,
            llm_analysis_mode,
        )

    config = load_config_from_env(
        analysis_backend_override=analysis_backend,
        llm_analysis_mode_override=llm_analysis_mode,
    )
    config.cache_read_enabled = not refresh_specs
    config.cache_dir = str(EVALUATION_DIR / ".vtc-cache" / fixtures_dir.name)
    pipeline = SimplePipeline(config)
    report = EvaluationReport(analysis=_analysis_metadata(config))

    try:
        for rel_name, truth_for_file in truth.get("files", {}).items():
            path = fixtures_dir / rel_name
            if not path.exists():
                print(f"[skip] {rel_name} not found at {path}", file=sys.stderr)
                continue
            print(f"[run] {rel_name} ...", file=sys.stderr)
            fe = await _evaluate_file(pipeline, path, truth_for_file)
            # Use the relative path as identifier in the report
            fe.file = rel_name
            report.files.append(fe)
    finally:
        await pipeline.aclose()

    report.aggregate = _aggregate(report)
    return report


# ---------------------------------------------------------------------------
# Diff mode
# ---------------------------------------------------------------------------


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text())


def _diff(a_path: Path, b_path: Path) -> str:
    a = _load_json(a_path)
    b = _load_json(b_path)
    a_agg = a["aggregate"]
    b_agg = b["aggregate"]

    def delta(k: str) -> str:
        av = a_agg.get(k, 0)
        bv = b_agg.get(k, 0)
        d = bv - av
        sign = "+" if d > 0 else ""
        return f"{av} -> {bv} ({sign}{d})"

    lines = ["# Diff: baseline vs after", "", "| Metric | Baseline -> After (Δ) |", "|---|---|"]
    for k in [
        "total_tp",
        "total_fp",
        "total_fn",
        "total_unclassified",
        "precision",
        "precision_strict",
        "recall",
        "f1",
    ]:
        lines.append(f"| {k} | {delta(k)} |")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _serialize_report(report: EvaluationReport) -> Dict[str, Any]:
    return {
        "analysis": report.analysis,
        "aggregate": report.aggregate,
        "files": [
            {
                "file": f.file,
                "cve": f.cve,
                "expected_tp": f.expected_tp,
                "found_tp": f.found_tp,
                "fp": f.fp,
                "fn": f.fn,
                "unclassified": f.unclassified,
                "tp_matched": f.tp_matched,
                "fp_chains": f.fp_chains,
                "fn_chains": f.fn_chains,
                "unclassified_chains": f.unclassified_chains,
                "pipeline_metrics": f.pipeline_metrics,
                "error": f.error,
            }
            for f in report.files
        ],
    }


def _evaluate_one_project(
    project_name: str,
    fixtures_dir: Path,
    save: Optional[Path],
    report_md: Optional[Path],
    auto_route: bool,
    phase: str,
    refresh_specs: bool = False,
    analysis_backend: Optional[str] = None,
    llm_analysis_mode: Optional[str] = None,
) -> EvaluationReport:
    """Evaluate a single project. Optionally auto-route output to evaluation/<project>/."""
    truth_path = fixtures_dir / "ground_truth.json"
    if not truth_path.exists():
        raise SystemExit(f"ground_truth.json not found at {truth_path}")
    truth = json.loads(truth_path.read_text())
    report = asyncio.run(_run_evaluation(
        fixtures_dir,
        truth,
        refresh_specs,
        analysis_backend,
        llm_analysis_mode,
    ))

    if auto_route:
        out_dir = EVALUATION_DIR / project_name
        out_dir.mkdir(parents=True, exist_ok=True)
        if save is None:
            save = out_dir / f"{phase}.json"
        if report_md is None:
            report_md = out_dir / f"{phase}.md"

    if save is not None:
        save.parent.mkdir(parents=True, exist_ok=True)
        save.write_text(json.dumps(_serialize_report(report), indent=2))
        print(f"[saved] {save}", file=sys.stderr)
    if report_md is not None:
        report_md.parent.mkdir(parents=True, exist_ok=True)
        report_md.write_text(_render_md(report))
        print(f"[saved] {report_md}", file=sys.stderr)
    return report


def _print_aggregate_table(per_project: Dict[str, Dict[str, Any]]) -> None:
    """Compact one-line-per-project summary printed after --all-projects run."""
    print("\n# Aggregate across projects\n")
    print("| Project | TP | Known FP | FN | Other | Precision | P known | Recall | F1 |")
    print("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    grand = {"total_tp": 0, "total_fp": 0, "total_fn": 0, "total_unclassified": 0}
    for name, agg in per_project.items():
        for k in grand:
            grand[k] += agg.get(k, 0)
        print(
            f"| {name} | {agg['total_tp']} | {agg['total_fp']} | {agg['total_fn']} "
            f"| {agg['total_unclassified']} | {agg['precision']:.2%} "
            f"| {agg['precision_known']:.2%} "
            f"| {agg['recall']:.2%} | {agg['f1']:.4f} |"
        )
    denom_known = grand["total_tp"] + grand["total_fp"]
    denom_all = denom_known + grand["total_unclassified"]
    denom_r = grand["total_tp"] + grand["total_fn"]
    p = grand["total_tp"] / denom_all if denom_all else 0.0
    p_known = grand["total_tp"] / denom_known if denom_known else 0.0
    r = grand["total_tp"] / denom_r if denom_r else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    print(
        f"| **TOTAL** | {grand['total_tp']} | {grand['total_fp']} | {grand['total_fn']} "
        f"| {grand['total_unclassified']} | {p:.2%} | {p_known:.2%} | {r:.2%} | {f1:.4f} |"
    )


def run_evaluation_command(
    *,
    fixtures_dir: Optional[Path] = None,
    project: Optional[str] = None,
    all_projects: bool = False,
    save: Optional[Path] = None,
    report_md: Optional[Path] = None,
    baseline: bool = False,
    phase_label: Optional[str] = None,
    diff_paths: Optional[Tuple[Path, Path]] = None,
    refresh_specs: bool = False,
    analysis_backend: Optional[str] = None,
    llm_analysis_mode: Optional[str] = None,
) -> int:
    """Run an evaluation request shared by Click and the legacy wrapper."""
    if diff_paths:
        print(_diff(*diff_paths))
        return 0

    if phase_label and not re.fullmatch(r"[A-Za-z0-9._-]+", phase_label):
        print("--phase-label may contain only letters, digits, '.', '_' and '-'", file=sys.stderr)
        return 2
    phase = phase_label or ("baseline" if baseline else "after")

    if all_projects:
        if fixtures_dir or project:
            print("--all-projects is exclusive with --fixtures-dir / --project", file=sys.stderr)
            return 2
        projects = _list_projects()
        if not projects:
            print(f"No projects found under {REAL_WORLD_DIR}", file=sys.stderr)
            return 2
        per_project: Dict[str, Dict[str, Any]] = {}
        for name in projects:
            print(f"\n=== {name} ===", file=sys.stderr)
            report = _evaluate_one_project(
                project_name=name,
                fixtures_dir=REAL_WORLD_DIR / name,
                save=None,
                report_md=None,
                auto_route=True,
                phase=phase,
                refresh_specs=refresh_specs,
                analysis_backend=analysis_backend,
                llm_analysis_mode=llm_analysis_mode,
            )
            per_project[name] = report.aggregate
        _print_aggregate_table(per_project)
        return 0

    if project:
        if fixtures_dir:
            print("--project is exclusive with --fixtures-dir", file=sys.stderr)
            return 2
        selected_fixtures = REAL_WORLD_DIR / project
        project_name = project
        auto_route = True
    else:
        selected_fixtures = fixtures_dir or DEFAULT_FIXTURES_DIR
        project_name = selected_fixtures.name
        # Explicit fixture directories are commonly used by CI with explicit
        # output paths, so they do not auto-write into evaluation/.
        auto_route = False

    report = _evaluate_one_project(
        project_name=project_name,
        fixtures_dir=selected_fixtures,
        save=save,
        report_md=report_md,
        auto_route=auto_route,
        phase=phase,
        refresh_specs=refresh_specs,
        analysis_backend=analysis_backend,
        llm_analysis_mode=llm_analysis_mode,
    )
    print(_render_md(report))
    return 0
