# VTC Evaluation Report

## Aggregate metrics

| Metric | Value |
|--------|-------|
| Files analyzed | 1 |
| Files failed | 0 |
| True positives | 2 / 2 expected |
| False positives | 2 (matched FP patterns) |
| False negatives | 0 |
| Unclassified | 0 |
| Precision (TP / TP+FP) | 50.00% |
| Precision strict (TP / TP+FP+Uncl) | 50.00% |
| Recall | 100.00% |
| F1 | 0.6667 |

## Per-file breakdown

### CVE-2019-10076/LinkToTag.java
_CVE:_ CVE-2019-10076

- TP: 2 / 2
- FP (matched patterns): 2
- FN: 0
- Unclassified: 0
- Pipeline metrics: {'sources_found': 6, 'sinks_found': 3, 'sanitizers_found': 0, 'chains_found': 4, 'chains_verified': 4, 'verification_rate': 1.0, 'explanations_generated': 4, 'graph_nodes': 179, 'graph_edges': 36}

#### True Positives matched
- `title` (line 69) -> `out` (line 36) [type=xss, conf=0.77] == expected TP-1 (setTitle(String title) — attacker-controlled title attribute -> m_title field -> out.print(...m_title...))
- `access` (line 74) -> `out` (line 36) [type=xss, conf=0.77] == expected TP-2 (setAccesskey(String access) -> m_accesskey field -> out.print(...m_accesskey...))

#### False Positives (matched FP patterns)
- `m_pageName` -> `out` [type=xss, conf=0.70] — Internal JSP context fields
- `m_pageName` -> `url` [type=xss, conf=0.70] — Internal wiki context API
