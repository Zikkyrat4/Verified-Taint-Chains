# VTC Evaluation Report

## Aggregate metrics

| Metric | Value |
|--------|-------|
| Files analyzed | 1 |
| Files failed | 0 |
| True positives | 2 / 2 expected |
| False positives | 0 (matched FP patterns) |
| False negatives | 0 |
| Unclassified | 7 |
| Precision (TP / TP+FP) | 100.00% |
| Precision strict (TP / TP+FP+Uncl) | 22.22% |
| Recall | 100.00% |
| F1 | 1.0000 |

## Per-file breakdown

### CVE-2020-2261/PerfectoBuildWrapper.java
_CVE:_ CVE-2020-2261

- TP: 2 / 2
- FP (matched patterns): 0
- FN: 0
- Unclassified: 7
- Pipeline metrics: {'sources_found': 6, 'sinks_found': 8, 'sanitizers_found': 0, 'chains_found': 15, 'chains_verified': 9, 'verification_rate': 0.6, 'explanations_generated': 9, 'graph_nodes': 364, 'graph_edges': 119}

#### True Positives matched
- `perfectoConnectLocation` (line 158) -> `process` (line 169) [type=command_injection, conf=0.70] == expected TP-1 (getTunnelId() parameter perfectoConnectLocation (from job config) -> string concatenation into bash -c -> Runtime.getRuntime().exec(cmdArgs))
- `pcParameters` (line 166) -> `process` (line 169) [type=command_injection, conf=0.70] == expected TP-2 (pcParameters (job config field) -> baseCommand -> Runtime.getRuntime().exec)

#### Unclassified chains
- `perfectoConnectLocation` (line 158) -> `tunnelId` (line 234) [type=sql_injection, conf=0.82]
- `cloudName` (line 161) -> `process` (line 169) [type=command_injection, conf=0.70]
- `cloudName` (line 161) -> `tunnelId` (line 234) [type=sql_injection, conf=0.82]
- `apiKey` (line 219) -> `process` (line 169) [type=command_injection, conf=0.82]
- `apiKey` (line 219) -> `tunnelId` (line 234) [type=sql_injection, conf=0.95]
- `pcParameters` (line 166) -> `tunnelId` (line 234) [type=sql_injection, conf=0.82]
- `credentials` (line 218) -> `tunnelId` (line 234) [type=sql_injection, conf=0.95]
