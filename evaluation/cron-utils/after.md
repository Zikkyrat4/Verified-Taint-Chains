# VTC Evaluation Report

## Aggregate metrics

| Metric | Value |
|--------|-------|
| Files analyzed | 1 |
| Files failed | 0 |
| True positives | 0 / 1 expected |
| False positives | 3 (matched FP patterns) |
| False negatives | 1 |
| Unclassified | 2 |
| Precision (TP / TP+FP) | 0.00% |
| Precision strict (TP / TP+FP+Uncl) | 0.00% |
| Recall | 0.00% |
| F1 | 0.0000 |

## Per-file breakdown

### CVE-2021-41269/CronParser.java
_CVE:_ CVE-2021-41269

- TP: 0 / 1
- FP (matched patterns): 3
- FN: 1
- Unclassified: 2
- Pipeline metrics: {'sources_found': 4, 'sinks_found': 6, 'sanitizers_found': 0, 'chains_found': 5, 'chains_verified': 5, 'verification_rate': 1.0, 'explanations_generated': 5, 'graph_nodes': 183, 'graph_edges': 103}

#### False Positives (matched FP patterns)
- `expression` -> `results` [type=deserialization, conf=0.93] — Internal collection / model construction
- `cronDefinition` -> `results` [type=deserialization, conf=0.93] — Internal collection / model construction
- `fields` -> `results` [type=deserialization, conf=0.93] — Internal collection / model construction

#### False Negatives (expected TPs not found)
- TP-1: `expression` -> `expression` (parse(String expression) — user-controlled cron expression -> String.format("Failed to parse '%s'...", expression) -> IllegalArgumentException message -> EL evaluation in validator framework)

#### Unclassified chains
- `expression` (line 88) -> `replaced` (line 86) [type=deserialization, conf=0.93]
- `expression` (line 88) -> `expressionParts` (line 111) [type=deserialization, conf=0.93]
