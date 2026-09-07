# VTC Evaluation Report

## Aggregate metrics

| Metric | Value |
|--------|-------|
| Files analyzed | 4 |
| Files failed | 0 |
| True positives | 1 / 8 expected |
| False positives | 0 (matched FP patterns) |
| False negatives | 7 |
| Unclassified | 4 |
| Precision (TP / TP+FP) | 100.00% |
| Precision strict (TP / TP+FP+Uncl) | 20.00% |
| Recall | 12.50% |
| F1 | 0.2222 |

## Per-file breakdown

### OIDCLoginProtocol.java
_CVE:_ CVE-2024-2419

- TP: 1 / 3
- FP (matched patterns): 0
- FN: 2
- Unclassified: 0
- Pipeline metrics: {'sources_found': 5, 'sinks_found': 3, 'sanitizers_found': 3, 'chains_found': 1, 'chains_verified': 1, 'verification_rate': 1.0, 'explanations_generated': 1, 'graph_nodes': 486, 'graph_edges': 392}

#### True Positives matched
- `redirectUri` (line 392) -> `finalRedirectUri` (line 400) [type=open_redirect, conf=0.78] == expected TP-1 (authSession.getRedirectUri() -> redirectUri.build() in authenticated())

#### False Negatives (expected TPs not found)
- TP-2: `redirect` -> `redirectUri` (authSession.getRedirectUri() -> redirectUri.build() in sendError())
- TP-3: `redirectUri` -> `finalRedirectUri` (logoutSession.getAuthNote(LOGOUT_REDIRECT_URI) -> renderLogoutPage())

### SerializedBrokeredIdentityContext.java
_CVE:_ internal (Unsafe Deserialization patterns)

- TP: 0 / 4
- FP (matched patterns): 0
- FN: 4
- Unclassified: 1
- Pipeline metrics: {'sources_found': 7, 'sinks_found': 2, 'sanitizers_found': 1, 'chains_found': 1, 'chains_verified': 1, 'verification_rate': 1.0, 'explanations_generated': 1, 'graph_nodes': 265, 'graph_edges': 161}

#### False Negatives (expected TPs not found)
- TP-1: `value` -> `clazz` (value.getClazz() -> Reflections.classForName())
- TP-2: `value` -> `deserialized` (value.getData() -> serializer.deserialize() assigned to `deserialized` (line 294). Sink variable is the deserialization result `deserialized` — `ctxData` is not a variable in this code.)
- TP-3: `asString` -> `ctx` (authSession.getAuthNote() -> JsonSerialization.readValue())
- TP-4: `ctxEntry` -> `asBytes` (ctxEntry.getData() -> JsonSerialization.readValue())

#### Unclassified chains
- `asString` (line 244) -> `asBytes` (line 246) [type=deserialization, conf=0.78]

### CVE-2022-3782/RedirectUtils.java
_CVE:_ CVE-2022-3782

- TP: 0 / 0
- FP (matched patterns): 0
- FN: 0
- Unclassified: 0
- Pipeline metrics: {'sources_found': 3, 'sinks_found': 1, 'sanitizers_found': 11, 'chains_found': 1, 'chains_verified': 0, 'verification_rate': 0.0, 'explanations_generated': 0, 'graph_nodes': 243, 'graph_edges': 125}

### CVE-2022-4361/SamlService.java
_CVE:_ CVE-2022-4361

- TP: 0 / 1
- FP (matched patterns): 0
- FN: 1
- Unclassified: 3
- Pipeline metrics: {'sources_found': 35, 'sinks_found': 14, 'sanitizers_found': 3, 'chains_found': 3, 'chains_verified': 3, 'verification_rate': 1.0, 'explanations_generated': 3, 'graph_nodes': 1042, 'graph_edges': 1137}

#### False Negatives (expected TPs not found)
- TP-1: `redirectUri` -> `redirect` (getAssertionConsumerServiceURL (deserialized SAML XML) -> authSession.setRedirectUri)

#### Unclassified chains
- `samlRequest` (line 878) -> `relayState` (line 885) [type=open_redirect, conf=0.85]
- `samlResponse` (line 878) -> `relayState` (line 885) [type=open_redirect, conf=0.85]
- `artifact` (line 878) -> `relayState` (line 885) [type=open_redirect, conf=0.85]
