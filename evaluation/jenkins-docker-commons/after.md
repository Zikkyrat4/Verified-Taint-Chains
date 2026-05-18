# VTC Evaluation Report

## Aggregate metrics

| Metric | Value |
|--------|-------|
| Files analyzed | 1 |
| Files failed | 0 |
| True positives | 0 / 1 expected |
| False positives | 1 (matched FP patterns) |
| False negatives | 1 |
| Unclassified | 10 |
| Precision (TP / TP+FP) | 0.00% |
| Precision strict (TP / TP+FP+Uncl) | 0.00% |
| Recall | 0.00% |
| F1 | 0.0000 |

## Per-file breakdown

### CVE-2022-20617/DockerRegistryEndpoint.java
_CVE:_ CVE-2022-20617

- TP: 0 / 1
- FP (matched patterns): 1
- FN: 1
- Unclassified: 10
- Pipeline metrics: {'sources_found': 22, 'sinks_found': 14, 'sanitizers_found': 1, 'chains_found': 12, 'chains_verified': 11, 'verification_rate': 0.9166666666666666, 'explanations_generated': 11, 'graph_nodes': 433, 'graph_edges': 113}

#### False Positives (matched FP patterns)
- `credentialsId` -> `hash` [type=other, conf=0.95] — Credential ID, not user-routed in this flow

#### False Negatives (expected TPs not found)
- TP-1: `s` -> `url` (fromImageName(String s, ...) parameter -> regex matcher.group(2) -> new URL(...) used in subsequent shell context)

#### Unclassified chains
- `matcher` (line 128) -> `hash` (line 339) [type=other, conf=0.95]
- `url` (line 128) -> `hash` (line 339) [type=other, conf=0.95]
- `workspace` (line 235) -> `token` (line 258) [type=other, conf=0.95]
- `target` (line 250) -> `token` (line 258) [type=other, conf=0.95]
- `launcher` (line 273) -> `token` (line 258) [type=other, conf=0.95]
- `listener` (line 273) -> `token` (line 258) [type=other, conf=0.95]
- `dockerExecutable` (line 273) -> `token` (line 258) [type=other, conf=0.95]
- `obj` (line 344) -> `credentialsId` (line 223) [type=deserialization, conf=0.93]
- `obj` (line 344) -> `hash` (line 339) [type=other, conf=0.95]
- `other` (line 354) -> `credentialsId` (line 223) [type=deserialization, conf=0.93]
