# VTC Evaluation Report

## Analysis configuration

- Backend: `static`
- LLM analysis mode: `n/a`
- Provider: `n/a`
- Model: `n/a`
- Minimum confidence: `0.6`
- Verification: `both`
- Pathfinder: `astar`
- Joern: `True`
- LLM graph enrichment: `False`
- Stage 1 cache reads: `True`

## Aggregate metrics

| Metric | Value |
|--------|-------|
| Files analyzed | 1 |
| Files failed | 0 |
| True positives | 1 / 2 expected |
| Known false positives | 0 |
| False negatives | 1 |
| Other unmatched findings | 2 |
| Precision (all unmatched findings are FP) | 33.33% |
| Precision on known labels only (diagnostic) | 100.00% |
| Recall | 50.00% |
| F1 | 0.4000 |

## Per-file breakdown

### CVE-2020-2261/PerfectoBuildWrapper.java
_CVE:_ CVE-2020-2261

- TP: 1 / 2
- FP (matched patterns): 0
- FN: 1
- Unclassified: 2
- Pipeline metrics: {'sources_found': 3, 'sinks_found': 1, 'sanitizers_found': 0, 'chains_found': 3, 'chains_verified': 3, 'verification_rate': 1.0, 'explanations_generated': 3, 'graph_nodes': 363, 'graph_edges': 65, 'extraction_complete': True, 'extraction_errors': [], 'analysis_backend': 'static', 'llm_analysis_mode': 'targeted'}

#### True Positives matched
- `perfectoConnectLocation` (line 151) -> `cmdArgs` (line 167) [type=command_injection, conf=0.81] == expected TP-1 (getTunnelId() parameter perfectoConnectLocation (from job config) -> string concatenation into bash -c -> Runtime.getRuntime().exec(cmdArgs). True sink is the exec argument `cmdArgs`. NOTE: the LLM currently terminates the chain one hop earlier at the command string `baseCommand`, so this is a known FN until Stage-1 labels the exec argument as the sink. We do NOT move the goalpost to `baseCommand` — the honest sink is the exec call.)

#### False Negatives (expected TPs not found)
- TP-2: `pcParameters` -> `cmdArgs` (pcParameters (job config field) -> baseCommand -> Runtime.getRuntime().exec)

#### Unclassified chains
- `cloudName` (line 151) -> `cmdArgs` (line 167) [type=command_injection, conf=0.81]
- `apiKey` (line 151) -> `cmdArgs` (line 167) [type=command_injection, conf=0.81]
