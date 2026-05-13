# VTC Evaluation Report

## Aggregate metrics

| Metric | Value |
|--------|-------|
| Files analyzed | 1 |
| Files failed | 0 |
| True positives | 0 / 1 expected |
| False positives | 1 (matched FP patterns) |
| False negatives | 1 |
| Unclassified | 0 |
| Precision (TP / TP+FP) | 0.00% |
| Precision strict (TP / TP+FP+Uncl) | 0.00% |
| Recall | 0.00% |
| F1 | 0.0000 |

## Per-file breakdown

### CVE-2022-22965/CachedIntrospectionResults.java
_CVE:_ CVE-2022-22965

- TP: 0 / 1
- FP (matched patterns): 1
- FN: 1
- Unclassified: 0
- Pipeline metrics: {'sources_found': 2, 'sinks_found': 1, 'sanitizers_found': 0, 'chains_found': 1, 'chains_verified': 1, 'verification_rate': 1.0, 'explanations_generated': 1, 'graph_nodes': 441, 'graph_edges': 107}

#### False Positives (matched FP patterns)
- `beanClass` -> `pd` [type=sql_injection, conf=0.70] — Internal iteration variables

#### False Negatives (expected TPs not found)
- TP-1: `beanClass` -> `beanInfo` (Constructor beanClass parameter (request-derived via data binding) -> getBeanInfo(beanClass) -> Introspector.getBeanInfo, exposing classLoader/protectionDomain getters that can be reached via property paths like class.module.classLoader.URLs[0])
