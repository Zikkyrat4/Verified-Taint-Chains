# VTC Evaluation Report

## Aggregate metrics

| Metric | Value |
|--------|-------|
| Files analyzed | 1 |
| Files failed | 0 |
| True positives | 0 / 2 expected |
| False positives | 1 (matched FP patterns) |
| False negatives | 2 |
| Unclassified | 2 |
| Precision (TP / TP+FP) | 0.00% |
| Precision strict (TP / TP+FP+Uncl) | 0.00% |
| Recall | 0.00% |
| F1 | 0.0000 |

## Per-file breakdown

### CVE-2019-10076/LinkToTag.java
_CVE:_ CVE-2019-10076

- TP: 0 / 2
- FP (matched patterns): 1
- FN: 2
- Unclassified: 2
- Pipeline metrics: {'sources_found': 7, 'sinks_found': 2, 'sanitizers_found': 0, 'chains_found': 3, 'chains_verified': 3, 'verification_rate': 1.0, 'explanations_generated': 3, 'graph_nodes': 179, 'graph_edges': 36}

#### False Positives (matched FP patterns)
- `m_pageName` -> `out` [type=other, conf=0.90] — Internal JSP context fields

#### False Negatives (expected TPs not found)
- TP-1: `title` -> `m_title` (setTitle(String title) — attacker-controlled title attribute -> m_title field -> out.print(...m_title...))
- TP-2: `access` -> `m_accesskey` (setAccesskey(String access) -> m_accesskey field -> out.print(...m_accesskey...))

#### Unclassified chains
- `title` (line 69) -> `out` (line 102) [type=other, conf=0.85]
- `access` (line 74) -> `out` (line 102) [type=other, conf=0.85]
