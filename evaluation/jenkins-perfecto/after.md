# VTC Evaluation Report

## Aggregate metrics

| Metric | Value |
|--------|-------|
| Files analyzed | 1 |
| Files failed | 0 |
| True positives | 0 / 1 expected |
| False positives | 0 (matched FP patterns) |
| False negatives | 1 |
| Unclassified | 10 |
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
- Unclassified: 10
- Pipeline metrics: {'sources_found': 21, 'sinks_found': 17, 'sanitizers_found': 0, 'chains_found': 13, 'chains_verified': 10, 'verification_rate': 0.7692307692307693, 'explanations_generated': 8, 'graph_nodes': 367, 'graph_edges': 118}

#### False Negatives (expected TPs not found)
- TP-1: `perfectoConnectLocation` -> `cmdArgs` (getTunnelId() parameter perfectoConnectLocation (from job config) -> string concatenation into bash -c -> Runtime.getRuntime().exec(cmdArgs))

#### Unclassified chains
- `perfectoConnectLocation` (line 158) -> `tunnelId` (line 176) [type=command_injection, conf=0.95]
- `perfectoConnectLocation` (line 158) -> `tunnelId` (line 234) [type=other, conf=0.95]
- `cloudName` (line 161) -> `tunnelId` (line 176) [type=command_injection, conf=0.95]
- `cloudName` (line 161) -> `tunnelId` (line 234) [type=other, conf=0.95]
- `apiKey` (line 160) -> `tunnelId` (line 176) [type=command_injection, conf=0.95]
- `apiKey` (line 160) -> `tunnelId` (line 234) [type=other, conf=0.95]
- `pcParameters` (line 163) -> `tunnelId` (line 176) [type=command_injection, conf=0.95]
- `pcParameters` (line 163) -> `tunnelId` (line 234) [type=other, conf=0.95]
- `credentials` (line 24) -> `tunnelId` (line 176) [type=command_injection, conf=0.95]
- `credentials` (line 24) -> `tunnelId` (line 234) [type=other, conf=0.95]
