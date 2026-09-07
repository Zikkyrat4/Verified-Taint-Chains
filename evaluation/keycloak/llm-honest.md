# VTC Evaluation Report

## Analysis configuration

- Backend: `llm`
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
| Files analyzed | 4 |
| Files failed | 0 |
| True positives | 0 / 9 expected |
| Known false positives | 0 |
| False negatives | 9 |
| Other unmatched findings | 26 |
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
- Unclassified: 3
- Pipeline metrics: {'sources_found': 8, 'sinks_found': 2, 'sanitizers_found': 0, 'chains_found': 3, 'chains_verified': 3, 'verification_rate': 1.0, 'explanations_generated': 3, 'graph_nodes': 486, 'graph_edges': 203, 'extraction_complete': True, 'extraction_errors': [], 'analysis_backend': 'llm', 'llm_analysis_mode': 'targeted'}

#### False Negatives (expected TPs not found)
- TP-1: `redirect` -> `redirectUri` (authSession.getRedirectUri() -> redirectUri.build() in authenticated())
- TP-2: `redirect` -> `redirectUri` (authSession.getRedirectUri() -> redirectUri.build() in sendError())
- TP-3: `redirectUri` -> `finalRedirectUri` (logoutSession.getAuthNote(LOGOUT_REDIRECT_URI) -> renderLogoutPage())

#### Unclassified chains
- `redirect` (line 215) -> `redirectUri` (line 216) [type=open_redirect, conf=0.85]
- `authSession` (line 244) -> `redirectUri` (line 216) [type=open_redirect, conf=0.82]
- `managementUrl` (line 452) -> `target` (line 456) [type=ssrf, conf=0.80]

### SerializedBrokeredIdentityContext.java
_CVE:_ internal (Unsafe Deserialization patterns)

- TP: 0 / 4
- FP (matched patterns): 0
- FN: 4
- Unclassified: 3
- Pipeline metrics: {'sources_found': 13, 'sinks_found': 4, 'sanitizers_found': 0, 'chains_found': 3, 'chains_verified': 3, 'verification_rate': 1.0, 'explanations_generated': 3, 'graph_nodes': 264, 'graph_edges': 101, 'extraction_complete': True, 'extraction_errors': [], 'analysis_backend': 'llm', 'llm_analysis_mode': 'targeted'}

#### False Negatives (expected TPs not found)
- TP-1: `value` -> `clazz` (value.getClazz() -> Reflections.classForName())
- TP-2: `value` -> `deserialized` (value.getData() -> serializer.deserialize() assigned to `deserialized` (line 294). Sink variable is the deserialization result `deserialized` — `ctxData` is not a variable in this code.)
- TP-3: `asString` -> `ctx` (authSession.getAuthNote() -> JsonSerialization.readValue())
- TP-4: `ctxEntry` -> `asBytes` (ctxEntry.getData() -> JsonSerialization.readValue())

#### Unclassified chains
- `contextData` (line 200) -> `asBytes` (line 245) [type=deserialization, conf=0.82]
- `asString` (line 244) -> `asBytes` (line 245) [type=deserialization, conf=0.82]
- `authSession` (line 266) -> `deserialized` (line 294) [type=deserialization, conf=0.82]

### CVE-2022-3782/RedirectUtils.java
_CVE:_ CVE-2022-3782

- TP: 0 / 1
- FP (matched patterns): 0
- FN: 1
- Unclassified: 0
- Pipeline metrics: {'sources_found': 0, 'sinks_found': 0, 'sanitizers_found': 0, 'chains_found': 0, 'chains_verified': 0, 'verification_rate': 0.0, 'explanations_generated': 0, 'graph_nodes': 0, 'graph_edges': 0, 'extraction_complete': True, 'extraction_errors': [], 'analysis_backend': 'llm', 'llm_analysis_mode': 'targeted'}

#### False Negatives (expected TPs not found)
- TP-1: `redirectUri` -> `redirectUri` (redirectUri parameter -> URI.create -> normalize -> return (path traversal via double encoding))

### CVE-2022-4361/SamlService.java
_CVE:_ CVE-2022-4361

- TP: 0 / 1
- FP (matched patterns): 0
- FN: 1
- Unclassified: 20
- Pipeline metrics: {'sources_found': 45, 'sinks_found': 16, 'sanitizers_found': 9, 'chains_found': 20, 'chains_verified': 20, 'verification_rate': 1.0, 'explanations_generated': 20, 'graph_nodes': 1039, 'graph_edges': 557, 'extraction_complete': True, 'extraction_errors': [], 'analysis_backend': 'llm', 'llm_analysis_mode': 'targeted'}

#### False Negatives (expected TPs not found)
- TP-1: `redirectUri` -> `redirect` (getAssertionConsumerServiceURL (deserialized SAML XML) -> authSession.setRedirectUri)

#### Unclassified chains
- `artifact` (line 1146) -> `artifactResponseString` (line 1214) [type=deserialization, conf=0.85]
- `relayState` (line 413) -> `requestAbstractType` (line 500) [type=other, conf=0.75]
- `inputStream` (line 1047) -> `soapBodyContents` (line 1059) [type=xxe, conf=0.82]
- `inputStream` (line 1047) -> `samlDocumentHolder` (line 1070) [type=deserialization, conf=0.82]
- `artifactResolveMessage` (line 1143) -> `artifact` (line 1163) [type=other, conf=0.90]
- `artifactResolveMessage` (line 1143) -> `artifactResponseString` (line 1214) [type=deserialization, conf=0.90]
- `artifactResolveMessage` (line 1143) -> `artifactResponseType` (line 1212) [type=xxe, conf=0.88]
- `artifactResolveMessage` (line 1143) -> `artifactResponseDocument` (line 1233) [type=other, conf=0.90]
- `artifact` (line 1146) -> `artifactResponseType` (line 1212) [type=xxe, conf=0.82]
- `artifact` (line 1146) -> `artifactResponseDocument` (line 1233) [type=other, conf=0.85]
- `artifactResponseString` (line 1196) -> `artifactResponseType` (line 1212) [type=xxe, conf=0.75]
- `artifactResponseString` (line 1196) -> `artifactResponseDocument` (line 1233) [type=other, conf=0.77]
- `artifactResponseDocument` (line 1258) -> `artifactResponseElement` (line 1259) [type=xxe, conf=0.72]
- `doc` (line 1386) -> `httpPost` (line 1386) [type=ssrf, conf=0.75]
- `clientArtifactBindingURI` (line 1386) -> `httpPost` (line 1386) [type=ssrf, conf=0.70]
- `soapBodyContents` (line 1048) -> `samlDocumentHolder` (line 1070) [type=deserialization, conf=0.80]
- `sessionMapping` (line 1162) -> `artifactResponseString` (line 1214) [type=deserialization, conf=0.85]
- `sessionMapping` (line 1162) -> `artifactResponseType` (line 1212) [type=xxe, conf=0.82]
- `sessionMapping` (line 1162) -> `artifactResponseDocument` (line 1233) [type=other, conf=0.85]
- `artifactResponseType` (line 1212) -> `artifactResponseDocument` (line 1233) [type=other, conf=0.88]
