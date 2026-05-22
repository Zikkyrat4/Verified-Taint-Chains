# VTC Evaluation Report

## Aggregate metrics

| Metric | Value |
|--------|-------|
| Files analyzed | 1 |
| Files failed | 0 |
| True positives | 1 / 1 expected |
| False positives | 0 (matched FP patterns) |
| False negatives | 0 |
| Unclassified | 12 |
| Precision (TP / TP+FP) | 100.00% |
| Precision strict (TP / TP+FP+Uncl) | 7.69% |
| Recall | 100.00% |
| F1 | 1.0000 |

## Per-file breakdown

### CVE-2020-2261/PerfectoBuildWrapper.java
_CVE:_ CVE-2020-2261

- TP: 1 / 1
- FP (matched patterns): 0
- FN: 0
- Unclassified: 12
- Pipeline metrics: {'sources_found': 11, 'sinks_found': 8, 'sanitizers_found': 0, 'chains_found': 17, 'chains_verified': 13, 'verification_rate': 0.7647058823529411, 'explanations_generated': 13, 'graph_nodes': 365, 'graph_edges': 125}

#### True Positives matched
- `perfectoConnectLocation` (line 151) -> `cmdArgs` (line 163) [type=command_injection, conf=0.95] == expected TP-1 (getTunnelId() parameter perfectoConnectLocation (from job config) -> string concatenation into bash -c -> Runtime.getRuntime().exec(cmdArgs). True sink is the exec argument `cmdArgs`. NOTE: the LLM currently terminates the chain one hop earlier at the command string `baseCommand`, so this is a known FN until Stage-1 labels the exec argument as the sink. We do NOT move the goalpost to `baseCommand` — the honest sink is the exec call.)

#### Unclassified chains
- `perfectoConnectLocation` (line 151) -> `tunnelId` (line 189) [type=xss, conf=0.90]
- `perfectoConnectLocation` (line 151) -> `tunnelId` (line 76) [type=other, conf=0.90]
- `cloudName` (line 151) -> `cmdArgs` (line 163) [type=command_injection, conf=0.95]
- `cloudName` (line 151) -> `tunnelId` (line 189) [type=xss, conf=0.90]
- `cloudName` (line 151) -> `tunnelId` (line 76) [type=other, conf=0.90]
- `apiKey` (line 151) -> `cmdArgs` (line 163) [type=command_injection, conf=0.95]
- `apiKey` (line 151) -> `tunnelId` (line 189) [type=xss, conf=0.90]
- `apiKey` (line 151) -> `tunnelId` (line 76) [type=other, conf=0.90]
- `credentials` (line 412) -> `tunnelId` (line 189) [type=xss, conf=0.80]
- `credentials` (line 412) -> `tunnelId` (line 76) [type=other, conf=0.80]
- `credentials` (line 412) -> `credentialId` (line 348) [type=open_redirect, conf=0.73]
- `project` (line 413) -> `credentialId` (line 348) [type=open_redirect, conf=0.78]
