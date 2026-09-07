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
| Files analyzed | 4 |
| Files failed | 0 |
| True positives | 0 / 9 expected |
| Known false positives | 2 |
| False negatives | 9 |
| Other unmatched findings | 30 |
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
- Unclassified: 2
- Pipeline metrics: {'sources_found': 10, 'sinks_found': 2, 'sanitizers_found': 3, 'chains_found': 2, 'chains_verified': 2, 'verification_rate': 1.0, 'explanations_generated': 2, 'graph_nodes': 486, 'graph_edges': 203, 'extraction_complete': True, 'extraction_errors': [], 'analysis_backend': 'hybrid', 'llm_analysis_mode': 'targeted'}

#### False Negatives (expected TPs not found)
- TP-1: `redirect` -> `redirectUri` (authSession.getRedirectUri() -> redirectUri.build() in authenticated())
- TP-2: `redirect` -> `redirectUri` (authSession.getRedirectUri() -> redirectUri.build() in sendError())
- TP-3: `redirectUri` -> `finalRedirectUri` (logoutSession.getAuthNote(LOGOUT_REDIRECT_URI) -> renderLogoutPage())

#### Unclassified chains
- `redirect` (line 215) -> `redirectUri` (line 216) [type=open_redirect, conf=0.88]
- `managementUrl` (line 452) -> `target` (line 456) [type=ssrf, conf=0.80]

### SerializedBrokeredIdentityContext.java
_CVE:_ internal (Unsafe Deserialization patterns)

- TP: 0 / 4
- FP (matched patterns): 0
- FN: 4
- Unclassified: 2
- Pipeline metrics: {'sources_found': 5, 'sinks_found': 4, 'sanitizers_found': 1, 'chains_found': 2, 'chains_verified': 2, 'verification_rate': 1.0, 'explanations_generated': 2, 'graph_nodes': 263, 'graph_edges': 91, 'extraction_complete': True, 'extraction_errors': [], 'analysis_backend': 'hybrid', 'llm_analysis_mode': 'targeted'}

#### False Negatives (expected TPs not found)
- TP-1: `value` -> `clazz` (value.getClazz() -> Reflections.classForName())
- TP-2: `value` -> `deserialized` (value.getData() -> serializer.deserialize() assigned to `deserialized` (line 294). Sink variable is the deserialization result `deserialized` — `ctxData` is not a variable in this code.)
- TP-3: `asString` -> `ctx` (authSession.getAuthNote() -> JsonSerialization.readValue())
- TP-4: `ctxEntry` -> `asBytes` (ctxEntry.getData() -> JsonSerialization.readValue())

#### Unclassified chains
- `noteKey` (line 343) -> `serializedCtx` (line 349) [type=deserialization, conf=0.81]
- `asString` (line 244) -> `asBytes` (line 245) [type=deserialization, conf=0.88]

### CVE-2022-3782/RedirectUtils.java
_CVE:_ CVE-2022-3782

- TP: 0 / 1
- FP (matched patterns): 0
- FN: 1
- Unclassified: 0
- Pipeline metrics: {'sources_found': 0, 'sinks_found': 0, 'sanitizers_found': 5, 'chains_found': 0, 'chains_verified': 0, 'verification_rate': 0.0, 'explanations_generated': 0, 'graph_nodes': 0, 'graph_edges': 0, 'extraction_complete': True, 'extraction_errors': [], 'analysis_backend': 'hybrid', 'llm_analysis_mode': 'targeted'}

#### False Negatives (expected TPs not found)
- TP-1: `redirectUri` -> `redirectUri` (redirectUri parameter -> URI.create -> normalize -> return (path traversal via double encoding))

### CVE-2022-4361/SamlService.java
_CVE:_ CVE-2022-4361

- TP: 0 / 1
- FP (matched patterns): 2
- FN: 1
- Unclassified: 26
- Pipeline metrics: {'sources_found': 59, 'sinks_found': 35, 'sanitizers_found': 13, 'chains_found': 28, 'chains_verified': 28, 'verification_rate': 1.0, 'explanations_generated': 28, 'graph_nodes': 1040, 'graph_edges': 561, 'extraction_complete': True, 'extraction_errors': [], 'analysis_backend': 'hybrid', 'llm_analysis_mode': 'targeted'}

#### False Positives (matched FP patterns)
- `relayState` -> `authSession` [type=other, conf=0.85] — Framework method
- `client` -> `authSession` [type=other, conf=0.70] — Framework method

#### False Negatives (expected TPs not found)
- TP-1: `redirectUri` -> `redirect` (getAssertionConsumerServiceURL (deserialized SAML XML) -> authSession.setRedirectUri)

#### Unclassified chains
- `samlRequest` (line 265) -> `documentHolder` (line 274) [type=deserialization, conf=0.92]
- `samlRequest` (line 265) -> `samlObject` (line 274) [type=deserialization, conf=0.89]
- `issuer` (line 243) -> `client` (line 244) [type=xxe, conf=0.90]
- `documentHolder` (line 274) -> `samlObject` (line 274) [type=deserialization, conf=0.88]
- `relayState` (line 413) -> `redirect` (line 426) [type=open_redirect, conf=0.85]
- `relayState` (line 413) -> `nameIdFormat` (line 470) [type=other, conf=0.85]
- `requestAbstractType` (line 413) -> `redirect` (line 426) [type=open_redirect, conf=0.85]
- `requestAbstractType` (line 413) -> `nameIdFormat` (line 470) [type=other, conf=0.85]
- `client` (line 413) -> `redirect` (line 426) [type=open_redirect, conf=0.70]
- `client` (line 413) -> `nameIdFormat` (line 470) [type=other, conf=0.70]
- `redirectUri` (line 424) -> `redirect` (line 426) [type=open_redirect, conf=0.85]
- `nameIdFormatUri` (line 468) -> `nameIdFormat` (line 470) [type=other, conf=0.85]
- `inputStream` (line 1047) -> `soapBodyContents` (line 1059) [type=xxe, conf=0.88]
- `inputStream` (line 1047) -> `samlDocumentHolder` (line 1052) [type=deserialization, conf=0.88]
- `artifactResolveMessage` (line 1143) -> `artifactResponseString` (line 1211) [type=deserialization, conf=0.93]
- `artifactResolveMessage` (line 1143) -> `artifact` (line 1155) [type=other, conf=0.88]
- `artifactResolveMessage` (line 1143) -> `artifactResponseDocument` (line 1212) [type=xxe, conf=0.82]
- `artifactResponseString` (line 1196) -> `artifactResponseDocument` (line 1212) [type=xxe, conf=0.75]
- `artifactResponseDocument` (line 1258) -> `artifactResponseElement` (line 1259) [type=xxe, conf=0.75]
- `clientModel` (line 1264) -> `canonicalization` (line 1273) [type=other, conf=0.60]
- `samlClient` (line 1270) -> `canonicalization` (line 1273) [type=other, conf=0.60]
- `doc` (line 1386) -> `httpPost` (line 1386) [type=ssrf, conf=0.70]
- `clientArtifactBindingURI` (line 1386) -> `httpPost` (line 1386) [type=ssrf, conf=0.60]
- `result` (line 1395) -> `soapBodyContents` (line 1398) [type=xxe, conf=0.65]
- `result` (line 1395) -> `samlDoc` (line 1399) [type=deserialization, conf=0.70]
- `soapBodyContents` (line 1398) -> `samlDoc` (line 1399) [type=deserialization, conf=0.75]
