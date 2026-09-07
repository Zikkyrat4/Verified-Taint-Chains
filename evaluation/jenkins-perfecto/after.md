# VTC Evaluation Report

## Aggregate metrics

| Metric | Value |
|--------|-------|
| Files analyzed | 1 |
| Files failed | 0 |
| True positives | 0 / 1 expected |
| False positives | 0 (matched FP patterns) |
| False negatives | 1 |
| Unclassified | 0 |
| Precision (TP / TP+FP) | 0.00% |
| Precision strict (TP / TP+FP+Uncl) | 0.00% |
| Recall | 0.00% |
| F1 | 0.0000 |

## Per-file breakdown

### CVE-2020-2261/PerfectoBuildWrapper.java
_CVE:_ CVE-2020-2261

- TP: 0 / 1
- FP (matched patterns): 0
- FN: 1
- Unclassified: 0
- Pipeline metrics: {'sources_found': 2, 'sinks_found': 0, 'sanitizers_found': 0, 'chains_found': 0, 'chains_verified': 0, 'verification_rate': 0.0, 'explanations_generated': 0, 'graph_nodes': 363, 'graph_edges': 115}

#### False Negatives (expected TPs not found)
- TP-1: `perfectoConnectLocation` -> `cmdArgs` (getTunnelId() parameter perfectoConnectLocation (from job config) -> string concatenation into bash -c -> Runtime.getRuntime().exec(cmdArgs). True sink is the exec argument `cmdArgs`. NOTE: the LLM currently terminates the chain one hop earlier at the command string `baseCommand`, so this is a known FN until Stage-1 labels the exec argument as the sink. We do NOT move the goalpost to `baseCommand` — the honest sink is the exec call.)
