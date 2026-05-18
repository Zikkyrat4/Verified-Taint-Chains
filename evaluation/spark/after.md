# VTC Evaluation Report

## Aggregate metrics

| Metric | Value |
|--------|-------|
| Files analyzed | 1 |
| Files failed | 0 |
| True positives | 0 / 1 expected |
| False positives | 3 (matched FP patterns) |
| False negatives | 1 |
| Unclassified | 1 |
| Precision (TP / TP+FP) | 0.00% |
| Precision strict (TP / TP+FP+Uncl) | 0.00% |
| Recall | 0.00% |
| F1 | 0.0000 |

## Per-file breakdown

### CVE-2018-9159/ClassPathResource.java
_CVE:_ CVE-2018-9159

- TP: 0 / 1
- FP (matched patterns): 3
- FN: 1
- Unclassified: 1
- Pipeline metrics: {'sources_found': 12, 'sinks_found': 10, 'sanitizers_found': 3, 'chains_found': 9, 'chains_verified': 4, 'verification_rate': 0.4444444444444444, 'explanations_generated': 4, 'graph_nodes': 210, 'graph_edges': 50}

#### False Positives (matched FP patterns)
- `relativePath` -> `builder` [type=other, conf=0.88] — Local string assembly in getDescription
- `path` -> `builder` [type=other, conf=0.90] — Local string assembly in getDescription
- `obj` -> `builder` [type=other, conf=0.90] — Local string assembly in getDescription

#### False Negatives (expected TPs not found)
- TP-1: `path` -> `path` (Constructor `path` parameter -> StringUtils.cleanPath -> this.path -> classLoader.getResourceAsStream(this.path))

#### Unclassified chains
- `path` (line 206) -> `is` (line 143) [type=other, conf=0.95]
