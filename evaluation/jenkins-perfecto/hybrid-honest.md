# VTC Evaluation Report

## Analysis configuration

- Backend: `hybrid`
- LLM analysis mode: `targeted`
- Provider: `openai`
- Model: `glm-5.3-flash`
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
| True positives | 2 / 2 expected |
| Known false positives | 0 |
| False negatives | 0 |
| Other unmatched findings | 2 |
| Precision (all unmatched findings are FP) | 50.00% |
| Precision on known labels only (diagnostic) | 100.00% |
| Recall | 100.00% |
| F1 | 0.6667 |

## Per-file breakdown

### CVE-2020-2261/PerfectoBuildWrapper.java
_CVE:_ CVE-2020-2261

- TP: 2 / 2
- FP (matched patterns): 0
- FN: 0
- Unclassified: 2
- Pipeline metrics: {'sources_found': 9, 'sinks_found': 2, 'sanitizers_found': 3, 'chains_found': 4, 'chains_verified': 4, 'verification_rate': 1.0, 'explanations_generated': 4, 'graph_nodes': 364, 'graph_edges': 67, 'extraction_complete': True, 'extraction_errors': [], 'analysis_backend': 'hybrid', 'llm_analysis_mode': 'targeted'}

#### True Positives matched
- `perfectoConnectLocation` (line 151) -> `cmdArgs` (line 167) [type=command_injection, conf=0.81] == expected TP-1 (getTunnelId() parameter perfectoConnectLocation (from job config) -> string concatenation into bash -c -> Runtime.getRuntime().exec(cmdArgs). True sink is the exec argument `cmdArgs`. NOTE: the LLM currently terminates the chain one hop earlier at the command string `baseCommand`, so this is a known FN until Stage-1 labels the exec argument as the sink. We do NOT move the goalpost to `baseCommand` — the honest sink is the exec call.)
- `pcParameters` (line 146) -> `cmdArgs` (line 167) [type=command_injection, conf=0.85] == expected TP-2 (pcParameters (job config field) -> baseCommand -> Runtime.getRuntime().exec)

#### Unclassified chains
- `cloudName` (line 151) -> `cmdArgs` (line 167) [type=command_injection, conf=0.81]
- `apiKey` (line 151) -> `cmdArgs` (line 167) [type=command_injection, conf=0.81]
