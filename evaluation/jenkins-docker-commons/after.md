# VTC Evaluation Report

## Aggregate metrics

| Metric | Value |
|--------|-------|
| Files analyzed | 1 |
| Files failed | 0 |
| True positives | 0 / 1 expected |
| False positives | 0 (matched FP patterns) |
| False negatives | 1 |
| Unclassified | 2 |
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
- Unclassified: 2
- Pipeline metrics: {'sources_found': 7, 'sinks_found': 14, 'sanitizers_found': 1, 'chains_found': 3, 'chains_verified': 2, 'verification_rate': 0.6666666666666666, 'explanations_generated': 2, 'graph_nodes': 430, 'graph_edges': 115}

#### False Negatives (expected TPs not found)
- TP-1: `s` -> `url` (fromImageName(String s, ...) parameter -> regex matcher.group(2) -> new URL(...) used in subsequent shell context)

#### Unclassified chains
- `build` (line 235) -> `token` (line 258) [type=sql_injection, conf=0.70]
- `build` (line 235) -> `workspace` (line 288) [type=command_injection, conf=0.70]
