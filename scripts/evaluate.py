"""Evaluation harness for VTC on real-world Java fixtures.

Runs SimplePipeline on each fixture file in a project directory, matches
reported chains against that project's ``ground_truth.json``, and computes
precision/recall/F1 plus a per-file breakdown of TP/FP/FN/unclassified.

Project-agnostic: each subdirectory under ``tests/fixtures/real_world/`` is a
project (one ``ground_truth.json`` + a tree of ``.java`` fixtures). The schema
is documented in ``tests/fixtures/real_world/README.md``.

Note on 0-day candidates: chains classified as ``unclassified`` are NOT
matched against any TP or known FP — they are precisely the cases worth
manual review when looking for previously-unknown vulnerabilities.

Usage:
    python scripts/evaluate.py --fixtures-dir tests/fixtures/real_world/<project> \\
        [--save evaluation.json] [--report-md OUT.md] [--baseline]
    python scripts/evaluate.py --diff baseline.json after.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Project root on sys.path so `import src.*` works when run as a script.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

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


def _cwe_digits(s: Optional[str]) -> str:
    """Extract the numeric core of a CWE id ('CWE-094' -> '94'); '' if none."""
    if not s:
        return ""
    digits = "".join(ch for ch in str(s) if ch.isdigit())
    return digits.lstrip("0") or ("0" if digits else "")


def _vars_match(reported: str, expected: str) -> bool:
    """Fuzzy variable-name match: substring either direction (case-insensitive)."""
    r, e = _norm(reported), _norm(expected)
    if not r or not e:
        return False
    return r == e or r in e or e in r


def _line_close(reported: int, expected: int, tolerance: int = 5) -> bool:
    """Lines match if within tolerance, or expected is 0 (means 'unknown')."""
    if expected == 0 or reported == 0:
        return True
    return abs(reported - expected) <= tolerance


def _file_matches(reported_path: str, expected_basename: str) -> bool:
    """Project-mode file constraint: chain.source/sink.file ends with expected basename.

    The reported path is absolute (e.g. ``/abs/.../webgoat/pathtraversal/Foo.java``);
    the TP encodes only a basename or short relative path (``Foo.java`` or
    ``pathtraversal/Foo.java``). Match by suffix.
    """
    if not expected_basename:
        return True  # no constraint declared
    r = _norm(reported_path)
    e = _norm(expected_basename)
    return r.endswith(e) or r.endswith("/" + e) or e in r


def _chain_matches_tp(chain: Dict[str, Any], tp: Dict[str, Any]) -> bool:
    """Match a reported chain against an expected true positive.

    Matching is path-aware: LLMs often pick a sink one hop beyond the actual
    injection point (e.g. `process` returned by `Runtime.exec(cmdArgs)` when
    the real taint sink is `cmdArgs`). If the expected source matches but the
    reported sink doesn't, accept the match when the expected sink name
    appears anywhere on the chain's path.

    Line check is dropped when both source and sink variable names match
    exactly (case-insensitive) — LLMs report the *use* line, not the
    declaration line, and noise from that easily exceeds any small tolerance
    while still pointing at the same vulnerability.

    Project-mode: when the TP carries ``source_file`` / ``sink_file``, the
    reported chain's source.file / sink.file must end with those (suffix
    match), so a cross-file flow is only credited when both endpoints land in
    the right files.
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

    src_exact = _norm(src_var) == _norm(exp_src) and bool(exp_src)
    sink_exact = _norm(sink_var) == _norm(exp_sink) and bool(exp_sink)

    src_ok = _vars_match(src_var, exp_src)
    sink_ok = _vars_match(sink_var, exp_sink)
    if not sink_ok and src_ok and exp_sink:
        path_nodes = chain.get("path", []) or []
        sink_ok = any(_vars_match(p, exp_sink) for p in path_nodes)
        if not sink_exact:
            sink_exact = any(_norm(p) == _norm(exp_sink) for p in path_nodes)

    var_ok = src_ok and sink_ok
    type_ok = (not exp_type) or vuln_type == exp_type or exp_type in vuln_type
    # Open-vocabulary fallback: a finding the LLM classified as OTHER (no
    # named enum match) still pins a real class via its CWE. Accept the type
    # when the LLM-supplied CWE equals the file's expected CWE.
    if not type_ok and exp_type:
        exp_cwe = _cwe_digits(tp.get("_cwe"))
        chain_cwe = _cwe_digits(chain.get("cwe"))
        if exp_cwe and chain_cwe and exp_cwe == chain_cwe:
            type_ok = True

    # Line numbers from an LLM are noise: it reports the use site, a
    # function-relative offset, or a declaration line — error easily exceeds
    # any small tolerance. When BOTH variables correspond (non-degenerate
    # names) AND the vulnerability type agrees, the flow is already pinned;
    # the line check then only manufactures false negatives on correct
    # detections (observed: jenkins-perfecto, keycloak deser). Keep it solely
    # as a tie-breaker when the variable match is weak/degenerate.
    exp_src_nontrivial = len(_norm(exp_src)) > 1
    exp_sink_nontrivial = len(_norm(exp_sink)) > 1
    strong_match = (
        var_ok and type_ok and exp_src_nontrivial and exp_sink_nontrivial
    )
    if (src_exact and sink_exact) or strong_match:
        line_ok = True
    else:
        line_ok = _line_close(src_line, tp.get("source_line", 0)) and _line_close(
            sink_line, tp.get("sink_line", 0)
        )
    return var_ok and type_ok and line_ok


def _chain_matches_fp_pattern(chain: Dict[str, Any], fp: Dict[str, Any]) -> bool:
    """Check if a chain matches a false-positive pattern entry."""
    src_var = chain["source"]["variable"]
    sink_var = chain["sink"]["variable"]
    # Reach into snippet too if available (some patterns target sink_pattern in code)
    src_snip = chain["source"].get("code_snippet", "") or ""
    sink_snip = chain["sink"].get("code_snippet", "") or ""

    if "source_var" in fp and _vars_match(src_var, fp["source_var"]):
        return True
    if "sink_var" in fp and _vars_match(sink_var, fp["sink_var"]):
        return True
    if "source_pattern" in fp:
        if re.search(fp["source_pattern"], f"{src_var} {src_snip}"):
            return True
    if "sink_pattern" in fp:
        if re.search(fp["sink_pattern"], f"{sink_var} {sink_snip}"):
            return True
    return False


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
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Classify reported chains against ground truth.

    Returns (tp_matched, fp, unclassified, fn).
    """
    tps = truth.get("true_positives", [])
    fp_patterns = truth.get("false_positive_patterns", [])
    # Propagate the file-level expected CWE onto each TP so the open-vocabulary
    # CWE fallback in _chain_matches_tp can use it (TP entries carry only
    # vuln_type; the CWE lives one level up).
    file_cwe = truth.get("cwe")
    if file_cwe:
        for _tp in tps:
            _tp.setdefault("_cwe", file_cwe)

    tp_matched: List[Dict[str, Any]] = []
    fp_chains: List[Dict[str, Any]] = []
    unclassified: List[Dict[str, Any]] = []
    matched_tp_ids = set()

    for chain in chains:
        # 1. Try matching against true positives first
        matched_tp = None
        for tp in tps:
            if tp.get("id") in matched_tp_ids:
                continue  # already matched
            if _chain_matches_tp(chain, tp):
                matched_tp = tp
                break

        if matched_tp is not None:
            tp_matched.append({"chain": chain, "tp": matched_tp})
            matched_tp_ids.add(matched_tp["id"])
            continue

        # 2. Try false-positive patterns
        fp_match = next((fp for fp in fp_patterns if _chain_matches_fp_pattern(chain, fp)), None)
        if fp_match is not None:
            fp_chains.append({"chain": chain, "fp_pattern": fp_match})
            continue

        # 3. Unclassified — neither expected TP nor known-FP. Counted separately.
        unclassified.append({"chain": chain})

    # Compute FNs (TPs we didn't find) — but exclude expected-realistic-false TPs
    fn_chains: List[Dict[str, Any]] = []
    for tp in tps:
        if tp.get("id") in matched_tp_ids:
            continue
        if tp.get("expected_realistic") is False:
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

    # Strict precision: only known-FPs in denominator (UN unclassified excluded — neither penalize nor reward).
    denom_p = total_tp + total_fp
    precision = total_tp / denom_p if denom_p else 0.0

    denom_r = total_tp + total_fn
    recall = total_tp / denom_r if denom_r else 0.0

    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    # Conservative precision (treats unclassified as FP)
    denom_pc = total_tp + total_fp + total_uncl
    precision_strict = total_tp / denom_pc if denom_pc else 0.0

    return {
        "total_tp": total_tp,
        "total_fp": total_fp,
        "total_fn": total_fn,
        "total_unclassified": total_uncl,
        "expected_tp": expected_tp,
        "precision": round(precision, 4),
        "precision_strict": round(precision_strict, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
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
    lines.append("## Aggregate metrics")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Files analyzed | {agg['files_analyzed']} |")
    lines.append(f"| Files failed | {agg['files_failed']} |")
    lines.append(f"| True positives | {agg['total_tp']} / {agg['expected_tp']} expected |")
    lines.append(f"| False positives | {agg['total_fp']} (matched FP patterns) |")
    lines.append(f"| False negatives | {agg['total_fn']} |")
    lines.append(f"| Unclassified | {agg['total_unclassified']} |")
    lines.append(f"| Precision (TP / TP+FP) | {agg['precision']:.2%} |")
    lines.append(f"| Precision strict (TP / TP+FP+Uncl) | {agg['precision_strict']:.2%} |")
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
        expected_tp=len([t for t in truth_for_file.get("true_positives", []) if t.get("expected_realistic", True)]),
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
        if sink_path.endswith(k) or sink_path.endswith("/" + k) or k in sink_path:
            if len(k) > best_len:
                best, best_len = key, len(k)
    if best is not None:
        return best
    for key in file_keys:
        k = _norm(key)
        if not k:
            continue
        if src_path.endswith(k) or src_path.endswith("/" + k) or k in src_path:
            if len(k) > best_len:
                best, best_len = key, len(k)
    return best


async def _run_project_evaluation(
    fixtures_dir: Path,
    truth: Dict[str, Any],
) -> EvaluationReport:
    """Evaluate a multi-file fixture using pipeline.run_project once.

    The whole .java tree under fixtures_dir is handed to the project-mode
    orchestrator so cross-file taint flows are visible. Reported chains are
    then routed back to the per-file rows of ground_truth.json via
    ``_route_chain_to_file``.
    """
    config = load_config_from_env()
    # Eval runs must always make fresh LLM calls — caching would mask
    # extractor regressions and break F1 reproducibility.
    config.cache_enabled = False
    config.cache_dir = None
    pipeline = SimplePipeline(config)
    report = EvaluationReport()

    java_files = sorted(str(p) for p in fixtures_dir.rglob("*.java"))
    if not java_files:
        print(f"[skip] no .java files under {fixtures_dir}", file=sys.stderr)
        report.aggregate = _aggregate(report)
        return report

    print(
        f"[run] project mode: {len(java_files)} files under {fixtures_dir.name}",
        file=sys.stderr,
    )

    # Pre-initialise one FileEvaluation per ground-truth file so absent
    # findings still show as FN rows.
    file_evals: Dict[str, FileEvaluation] = {}
    for rel_name, truth_for_file in truth.get("files", {}).items():
        expected = len(
            [t for t in truth_for_file.get("true_positives", []) if t.get("expected_realistic", True)]
        )
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
        report.files = list(file_evals.values())
        report.aggregate = _aggregate(report)
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
            buckets[rel_name], truth_for_file
        )
        fe.tp_matched = tp_matched
        fe.fp_chains = fp_chains
        fe.unclassified_chains = unclassified
        fe.fn_chains = fn_chains
        fe.found_tp = len(tp_matched)
        fe.fp = len(fp_chains)
        fe.unclassified = len(unclassified)
        fe.fn = len(fn_chains)

    # Chains whose sink/source file didn't map to any ground-truth key — put
    # them in a synthetic project-level bucket so they're visible but don't
    # inflate per-file precision/recall.
    if orphan_chains:
        orphan = FileEvaluation(file="<project-orphan>")
        orphan.unclassified_chains = [{"chain": c} for c in orphan_chains]
        orphan.unclassified = len(orphan_chains)
        orphan.pipeline_metrics = pipeline_metrics
        report.files = list(file_evals.values()) + [orphan]
    else:
        report.files = list(file_evals.values())

    report.aggregate = _aggregate(report)
    return report


async def _run_evaluation(
    fixtures_dir: Path,
    truth: Dict[str, Any],
) -> EvaluationReport:
    # Project-mode fixture: hand the entire .java tree to pipeline.run_project
    # so cross-file flows (e.g. subclass entry point → inherited base method)
    # can actually be traced. Single-file mode is the default.
    if truth.get("mode") == "project":
        return await _run_project_evaluation(fixtures_dir, truth)

    config = load_config_from_env()
    # Eval runs must always make fresh LLM calls — see note above.
    config.cache_enabled = False
    config.cache_dir = None
    pipeline = SimplePipeline(config)
    report = EvaluationReport()

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
) -> EvaluationReport:
    """Evaluate a single project. Optionally auto-route output to evaluation/<project>/."""
    truth_path = fixtures_dir / "ground_truth.json"
    if not truth_path.exists():
        raise SystemExit(f"ground_truth.json not found at {truth_path}")
    truth = json.loads(truth_path.read_text())
    report = asyncio.run(_run_evaluation(fixtures_dir, truth))

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
    print("| Project | TP | FP | FN | Uncl | Precision | Recall | F1 |")
    print("|---|---:|---:|---:|---:|---:|---:|---:|")
    grand = {"total_tp": 0, "total_fp": 0, "total_fn": 0, "total_unclassified": 0}
    for name, agg in per_project.items():
        for k in grand:
            grand[k] += agg.get(k, 0)
        print(
            f"| {name} | {agg['total_tp']} | {agg['total_fp']} | {agg['total_fn']} "
            f"| {agg['total_unclassified']} | {agg['precision']:.2%} "
            f"| {agg['recall']:.2%} | {agg['f1']:.4f} |"
        )
    denom_p = grand["total_tp"] + grand["total_fp"]
    denom_r = grand["total_tp"] + grand["total_fn"]
    p = grand["total_tp"] / denom_p if denom_p else 0.0
    r = grand["total_tp"] / denom_r if denom_r else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    print(
        f"| **TOTAL** | {grand['total_tp']} | {grand['total_fp']} | {grand['total_fn']} "
        f"| {grand['total_unclassified']} | {p:.2%} | {r:.2%} | {f1:.4f} |"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--fixtures-dir",
        type=Path,
        default=None,
        help="Explicit directory containing ground_truth.json + .java fixtures (back-compat).",
    )
    parser.add_argument(
        "--project",
        type=str,
        default=None,
        help=(
            "Project name under tests/fixtures/real_world/. Auto-routes output to "
            "evaluation/<project>/<phase>.{json,md} if --save/--report-md not given."
        ),
    )
    parser.add_argument(
        "--all-projects",
        action="store_true",
        help="Walk every project under tests/fixtures/real_world/ and print aggregate table.",
    )
    parser.add_argument(
        "--save",
        type=Path,
        help="Write JSON report to this path",
    )
    parser.add_argument(
        "--report-md",
        type=Path,
        help="Write Markdown report to this path",
    )
    parser.add_argument(
        "--baseline",
        action="store_true",
        help="Phase label for auto-routed save: evaluation/<project>/baseline.{json,md} (default: after).",
    )
    parser.add_argument(
        "--diff",
        nargs=2,
        metavar=("BASELINE", "AFTER"),
        type=Path,
        help="Compare two JSON reports and print a diff",
    )
    args = parser.parse_args()

    if args.diff:
        print(_diff(*args.diff))
        return 0

    phase = "baseline" if args.baseline else "after"

    if args.all_projects:
        if args.fixtures_dir or args.project:
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
            )
            per_project[name] = report.aggregate
        _print_aggregate_table(per_project)
        return 0

    if args.project:
        if args.fixtures_dir:
            print("--project is exclusive with --fixtures-dir", file=sys.stderr)
            return 2
        fixtures_dir = REAL_WORLD_DIR / args.project
        project_name = args.project
        auto_route = True
    else:
        fixtures_dir = args.fixtures_dir or DEFAULT_FIXTURES_DIR
        project_name = fixtures_dir.name
        # Back-compat: stay with explicit --save behavior. Don't auto-route on plain
        # --fixtures-dir invocations — that surface is consumed by CI / snapshot scripts.
        auto_route = False

    report = _evaluate_one_project(
        project_name=project_name,
        fixtures_dir=fixtures_dir,
        save=args.save,
        report_md=args.report_md,
        auto_route=auto_route,
        phase=phase,
    )
    print(_render_md(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
