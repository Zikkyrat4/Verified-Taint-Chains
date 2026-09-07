# VTC Evaluation Report

## Aggregate metrics

| Metric | Value |
|--------|-------|
| Files analyzed | 1 |
| Files failed | 0 |
| True positives | 0 / 2 expected |
| False positives | 0 (matched FP patterns) |
| False negatives | 2 |
| Unclassified | 0 |
| Precision (TP / TP+FP) | 0.00% |
| Precision strict (TP / TP+FP+Uncl) | 0.00% |
| Recall | 0.00% |
| F1 | 0.0000 |

## Per-file breakdown

### CVE-2019-10076/LinkToTag.java
_CVE:_ CVE-2019-10076

- TP: 0 / 2
- FP (matched patterns): 0
- FN: 2
- Unclassified: 0
- Pipeline metrics: {'sources_found': 3, 'sinks_found': 0, 'sanitizers_found': 0, 'chains_found': 0, 'chains_verified': 0, 'verification_rate': 0.0, 'explanations_generated': 0, 'graph_nodes': 177, 'graph_edges': 34}

#### False Negatives (expected TPs not found)
- TP-1: `title` -> `m_title` (setTitle(String title) — attacker-controlled title attribute -> m_title field -> out.print(...m_title...))
- TP-2: `access` -> `m_accesskey` (setAccesskey(String access) -> m_accesskey field -> out.print(...m_accesskey...))
