# VTC Evaluation Report

## Aggregate metrics

| Metric | Value |
|--------|-------|
| Files analyzed | 1 |
| Files failed | 0 |
| True positives | 1 / 1 expected |
| False positives | 0 (matched FP patterns) |
| False negatives | 0 |
| Unclassified | 1 |
| Precision (TP / TP+FP) | 100.00% |
| Precision strict (TP / TP+FP+Uncl) | 50.00% |
| Recall | 100.00% |
| F1 | 1.0000 |

## Per-file breakdown

### CVE-2018-9159/ClassPathResource.java
_CVE:_ CVE-2018-9159

- TP: 1 / 1
- FP (matched patterns): 0
- FN: 0
- Unclassified: 1
- Pipeline metrics: {'sources_found': 5, 'sinks_found': 2, 'sanitizers_found': 3, 'chains_found': 2, 'chains_verified': 2, 'verification_rate': 1.0, 'explanations_generated': 2, 'graph_nodes': 209, 'graph_edges': 48}

#### True Positives matched
- `path` (line 141) -> `is` (line 146) [type=path_traversal, conf=0.70] == expected TP-1 (Constructor `path` parameter -> StringUtils.cleanPath -> this.path -> classLoader.getResourceAsStream(this.path))

#### Unclassified chains
- `path` (line 141) -> `url` (line 168) [type=xss, conf=0.70]
