# VTC Evaluation Report

## Analysis configuration

- Backend: `hybrid`
- LLM analysis mode: `targeted`
- Provider: `openai`
- Model: `glm-5.3-flash`
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
| Other unmatched findings | 1 |
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
- Unclassified: 1
- Pipeline metrics: {'sources_found': 7, 'sinks_found': 1, 'sanitizers_found': 3, 'chains_found': 1, 'chains_verified': 1, 'verification_rate': 1.0, 'explanations_generated': 1, 'graph_nodes': 430, 'graph_edges': 42, 'extraction_complete': True, 'extraction_errors': [], 'analysis_backend': 'hybrid', 'llm_analysis_mode': 'targeted'}

#### False Negatives (expected TPs not found)
- TP-1: `s` -> `url` (fromImageName(String s, ...) parameter -> regex matcher.group(2) -> new URL(...) used in subsequent shell context)

#### Unclassified chains
- `s` (line 120) -> `url` (line 128) [type=ssrf, conf=0.75]
