# VTC Evaluation Report

## Analysis configuration

- Backend: `static`
- LLM analysis mode: `n/a`
- Provider: `n/a`
- Model: `n/a`
- Minimum confidence: `0.6`
- Verification: `both`
- Pathfinder: `astar`
- Joern: `True`
- LLM graph enrichment: `False`
- Stage 1 cache reads: `True`

## Aggregate metrics

| Metric | Value |
|--------|-------|
| Files analyzed | 1 |
| Files failed | 0 |
| True positives | 0 / 1 expected |
| Known false positives | 0 |
| False negatives | 1 |
| Other unmatched findings | 0 |
| Precision (all unmatched findings are FP) | 0.00% |
| Precision on known labels only (diagnostic) | 0.00% |
| Recall | 0.00% |
| F1 | 0.0000 |

## Per-file breakdown

### CVE-2022-20617/DockerRegistryEndpoint.java
_CVE:_ CVE-2022-20617

- TP: 0 / 1
- FP (matched patterns): 0
- FN: 1
- Unclassified: 0
- Pipeline metrics: {'sources_found': 0, 'sinks_found': 0, 'sanitizers_found': 1, 'chains_found': 0, 'chains_verified': 0, 'verification_rate': 0.0, 'explanations_generated': 0, 'graph_nodes': 0, 'graph_edges': 0, 'extraction_complete': True, 'extraction_errors': [], 'analysis_backend': 'static', 'llm_analysis_mode': 'targeted'}

#### False Negatives (expected TPs not found)
- TP-1: `s` -> `url` (fromImageName(String s, ...) parameter -> regex matcher.group(2) -> new URL(...) used in subsequent shell context)
