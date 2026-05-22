# VTC Evaluation Report

## Aggregate metrics

| Metric | Value |
|--------|-------|
| Files analyzed | 1 |
| Files failed | 0 |
| True positives | 2 / 2 expected |
| False positives | 0 (matched FP patterns) |
| False negatives | 0 |
| Unclassified | 0 |
| Precision (TP / TP+FP) | 100.00% |
| Precision strict (TP / TP+FP+Uncl) | 100.00% |
| Recall | 100.00% |
| F1 | 1.0000 |

## Per-file breakdown

### CVE-2019-10076/LinkToTag.java
_CVE:_ CVE-2019-10076

- TP: 2 / 2
- FP (matched patterns): 0
- FN: 0
- Unclassified: 0
- Pipeline metrics: {'sources_found': 8, 'sinks_found': 4, 'sanitizers_found': 0, 'chains_found': 2, 'chains_verified': 2, 'verification_rate': 1.0, 'explanations_generated': 2, 'graph_nodes': 177, 'graph_edges': 35}

#### True Positives matched
- `title` (line 69) -> `m_title` (line 127) [type=xss, conf=0.82] == expected TP-1 (setTitle(String title) — attacker-controlled title attribute -> m_title field -> out.print(...m_title...))
- `access` (line 74) -> `m_accesskey` (line 127) [type=xss, conf=0.82] == expected TP-2 (setAccesskey(String access) -> m_accesskey field -> out.print(...m_accesskey...))
