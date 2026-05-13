# VTC Evaluation Report

## Aggregate metrics

| Metric | Value |
|--------|-------|
| Files analyzed | 1 |
| Files failed | 0 |
| True positives | 0 / 1 expected |
| False positives | 2 (matched FP patterns) |
| False negatives | 1 |
| Unclassified | 4 |
| Precision (TP / TP+FP) | 0.00% |
| Precision strict (TP / TP+FP+Uncl) | 0.00% |
| Recall | 0.00% |
| F1 | 0.0000 |

## Per-file breakdown

### CVE-2021-41269/CronParser.java
_CVE:_ CVE-2021-41269

- TP: 0 / 1
- FP (matched patterns): 2
- FN: 1
- Unclassified: 4
- Pipeline metrics: {'sources_found': 1, 'sinks_found': 6, 'sanitizers_found': 0, 'chains_found': 6, 'chains_verified': 6, 'verification_rate': 1.0, 'explanations_generated': 6, 'graph_nodes': 183, 'graph_edges': 104}

#### False Positives (matched FP patterns)
- `expression` -> `expressionParts` [type=command_injection, conf=0.70] — Stream helpers
- `expression` -> `expressionParts` [type=xxe, conf=0.70] — Internal recursive parser call

#### False Negatives (expected TPs not found)
- TP-1: `expression` -> `expression` (parse(String expression) — user-controlled cron expression -> String.format("Failed to parse '%s'...", expression) -> IllegalArgumentException message -> EL evaluation in validator framework)

#### Unclassified chains
- `expression` (line 92) -> `replaced` (line 86) [type=sql_injection, conf=0.70]
- `expression` (line 92) -> `expressionParts` (line 111) [type=xss, conf=0.70]
- `expression` (line 92) -> `expressionParts` (line 124) [type=sql_injection, conf=0.70]
- `expression` (line 92) -> `expressionParts` (line 111) [type=ssrf, conf=0.70]
