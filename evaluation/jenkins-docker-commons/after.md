# VTC Evaluation Report

## Aggregate metrics

| Metric | Value |
|--------|-------|
| Files analyzed | 1 |
| Files failed | 0 |
| True positives | 0 / 1 expected |
| False positives | 0 (matched FP patterns) |
| False negatives | 1 |
| Unclassified | 1 |
| Precision (TP / TP+FP) | 0.00% |
| Precision strict (TP / TP+FP+Uncl) | 0.00% |
| Recall | 0.00% |
| F1 | 0.0000 |

## Per-file breakdown

### CVE-2022-20617/DockerRegistryEndpoint.java
_CVE:_ CVE-2022-20617

- TP: 0 / 1
- FP (matched patterns): 0
- FN: 1
- Unclassified: 1
- Pipeline metrics: {'sources_found': 10, 'sinks_found': 7, 'sanitizers_found': 1, 'chains_found': 2, 'chains_verified': 1, 'verification_rate': 0.5, 'explanations_generated': 1, 'graph_nodes': 433, 'graph_edges': 115}

#### False Negatives (expected TPs not found)
- TP-1: `s` -> `url` (fromImageName(String s, ...) parameter -> regex matcher.group(2) -> new URL(...) used in subsequent shell context)

#### Unclassified chains
- `dockerExecutable` (line 281) -> `token` (line 254) [type=other, conf=0.80]
