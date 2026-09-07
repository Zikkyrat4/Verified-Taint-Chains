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
| Files analyzed | 4 |
| Files failed | 0 |
| True positives | 0 / 9 expected |
| Known false positives | 0 |
| False negatives | 9 |
| Other unmatched findings | 1 |
| Precision (all unmatched findings are FP) | 0.00% |
| Precision on known labels only (diagnostic) | 0.00% |
| Recall | 0.00% |
| F1 | 0.0000 |

## Per-file breakdown

### OIDCLoginProtocol.java
_CVE:_ CVE-2024-2419

- TP: 0 / 3
- FP (matched patterns): 0
- FN: 3
- Unclassified: 0
- Pipeline metrics: {'sources_found': 0, 'sinks_found': 0, 'sanitizers_found': 3, 'chains_found': 0, 'chains_verified': 0, 'verification_rate': 0.0, 'explanations_generated': 0, 'graph_nodes': 0, 'graph_edges': 0, 'extraction_complete': True, 'extraction_errors': [], 'analysis_backend': 'static', 'llm_analysis_mode': 'targeted'}

#### False Negatives (expected TPs not found)
- TP-1: `redirect` -> `redirectUri` (authSession.getRedirectUri() -> redirectUri.build() in authenticated())
- TP-2: `redirect` -> `redirectUri` (authSession.getRedirectUri() -> redirectUri.build() in sendError())
- TP-3: `redirectUri` -> `finalRedirectUri` (logoutSession.getAuthNote(LOGOUT_REDIRECT_URI) -> renderLogoutPage())

### SerializedBrokeredIdentityContext.java
_CVE:_ internal (Unsafe Deserialization patterns)

- TP: 0 / 4
- FP (matched patterns): 0
- FN: 4
- Unclassified: 1
- Pipeline metrics: {'sources_found': 1, 'sinks_found': 4, 'sanitizers_found': 1, 'chains_found': 1, 'chains_verified': 1, 'verification_rate': 1.0, 'explanations_generated': 1, 'graph_nodes': 263, 'graph_edges': 91, 'extraction_complete': True, 'extraction_errors': [], 'analysis_backend': 'static', 'llm_analysis_mode': 'targeted'}

#### False Negatives (expected TPs not found)
- TP-1: `value` -> `clazz` (value.getClazz() -> Reflections.classForName())
- TP-2: `value` -> `deserialized` (value.getData() -> serializer.deserialize() assigned to `deserialized` (line 294). Sink variable is the deserialization result `deserialized` — `ctxData` is not a variable in this code.)
- TP-3: `asString` -> `ctx` (authSession.getAuthNote() -> JsonSerialization.readValue())
- TP-4: `ctxEntry` -> `asBytes` (ctxEntry.getData() -> JsonSerialization.readValue())

#### Unclassified chains
- `noteKey` (line 343) -> `serializedCtx` (line 349) [type=deserialization, conf=0.81]

### CVE-2022-3782/RedirectUtils.java
_CVE:_ CVE-2022-3782

- TP: 0 / 1
- FP (matched patterns): 0
- FN: 1
- Unclassified: 0
- Pipeline metrics: {'sources_found': 0, 'sinks_found': 0, 'sanitizers_found': 5, 'chains_found': 0, 'chains_verified': 0, 'verification_rate': 0.0, 'explanations_generated': 0, 'graph_nodes': 0, 'graph_edges': 0, 'extraction_complete': True, 'extraction_errors': [], 'analysis_backend': 'static', 'llm_analysis_mode': 'targeted'}

#### False Negatives (expected TPs not found)
- TP-1: `redirectUri` -> `redirectUri` (redirectUri parameter -> URI.create -> normalize -> return (path traversal via double encoding))

### CVE-2022-4361/SamlService.java
_CVE:_ CVE-2022-4361

- TP: 0 / 1
- FP (matched patterns): 0
- FN: 1
- Unclassified: 0
- Pipeline metrics: {'sources_found': 11, 'sinks_found': 1, 'sanitizers_found': 2, 'chains_found': 0, 'chains_verified': 0, 'verification_rate': 0.0, 'explanations_generated': 0, 'graph_nodes': 1039, 'graph_edges': 557, 'extraction_complete': True, 'extraction_errors': [], 'analysis_backend': 'static', 'llm_analysis_mode': 'targeted'}

#### False Negatives (expected TPs not found)
- TP-1: `redirectUri` -> `redirect` (getAssertionConsumerServiceURL (deserialized SAML XML) -> authSession.setRedirectUri)
