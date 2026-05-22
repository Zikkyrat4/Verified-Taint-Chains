# VTC Evaluation Report

## Aggregate metrics

| Metric | Value |
|--------|-------|
| Files analyzed | 4 |
| Files failed | 0 |
| True positives | 2 / 8 expected |
| False positives | 6 (matched FP patterns) |
| False negatives | 6 |
| Unclassified | 207 |
| Precision (TP / TP+FP) | 25.00% |
| Precision strict (TP / TP+FP+Uncl) | 0.93% |
| Recall | 25.00% |
| F1 | 0.2500 |

## Per-file breakdown

### OIDCLoginProtocol.java
_CVE:_ CVE-2024-2419

- TP: 1 / 3
- FP (matched patterns): 4
- FN: 2
- Unclassified: 7
- Pipeline metrics: {'sources_found': 19, 'sinks_found': 8, 'sanitizers_found': 3, 'chains_found': 14, 'chains_verified': 12, 'verification_rate': 0.8571428571428571, 'explanations_generated': 12, 'graph_nodes': 489, 'graph_edges': 393}

#### True Positives matched
- `redirect` (line 324) -> `redirectUri` (line 330) [type=open_redirect, conf=0.90] == expected TP-1 (authSession.getRedirectUri() -> redirectUri.build() in authenticated())

#### False Positives (matched FP patterns)
- `state` -> `redirectUri` [type=open_redirect, conf=0.90] — Server-controlled framework values
- `state` -> `redirectUri` [type=ssrf, conf=0.88] — Server-controlled framework values
- `kcActionStatus` -> `redirectUri` [type=open_redirect, conf=0.88] — Server-controlled framework values
- `kcActionStatus` -> `redirectUri` [type=ssrf, conf=0.85] — Server-controlled framework values

#### False Negatives (expected TPs not found)
- TP-2: `redirect` -> `redirectUri` (authSession.getRedirectUri() -> redirectUri.build() in sendError())
- TP-3: `redirectUri` -> `finalRedirectUri` (logoutSession.getAuthNote(LOGOUT_REDIRECT_URI) -> renderLogoutPage())

#### Unclassified chains
- `redirect` (line 324) -> `redirectUri` (line 333) [type=ssrf, conf=0.88]
- `responseType` (line 166) -> `redirectUri` (line 330) [type=open_redirect, conf=0.88]
- `responseType` (line 166) -> `redirectUri` (line 333) [type=ssrf, conf=0.85]
- `responseMode` (line 166) -> `redirectUri` (line 330) [type=open_redirect, conf=0.88]
- `responseMode` (line 166) -> `redirectUri` (line 333) [type=ssrf, conf=0.85]
- `error` (line 329) -> `redirectUri` (line 330) [type=open_redirect, conf=0.85]
- `error` (line 329) -> `redirectUri` (line 333) [type=ssrf, conf=0.82]

### SerializedBrokeredIdentityContext.java
_CVE:_ internal (Unsafe Deserialization patterns)

- TP: 1 / 4
- FP (matched patterns): 0
- FN: 3
- Unclassified: 13
- Pipeline metrics: {'sources_found': 26, 'sinks_found': 13, 'sanitizers_found': 1, 'chains_found': 15, 'chains_verified': 14, 'verification_rate': 0.9333333333333333, 'explanations_generated': 14, 'graph_nodes': 272, 'graph_edges': 172}

#### True Positives matched
- `value` (line 215) -> `deserialized` (line 294) [type=deserialization, conf=0.85] == expected TP-2 (value.getData() -> serializer.deserialize() assigned to `deserialized` (line 294). Sink variable is the deserialization result `deserialized` — `ctxData` is not a variable in this code.)

#### False Negatives (expected TPs not found)
- TP-1: `value` -> `clazz` (value.getClazz() -> Reflections.classForName())
- TP-3: `asString` -> `ctx` (authSession.getAuthNote() -> JsonSerialization.readValue())
- TP-4: `ctxEntry` -> `asBytes` (ctxEntry.getData() -> JsonSerialization.readValue())

#### Unclassified chains
- `value` (line 215) -> `asBytes` (line 246) [type=deserialization, conf=0.85]
- `value` (line 215) -> `asString` (line 349) [type=deserialization, conf=0.85]
- `value` (line 215) -> `serializedValue` (line 327) [type=deserialization, conf=0.82]
- `key` (line 221) -> `asBytes` (line 246) [type=deserialization, conf=0.85]
- `key` (line 221) -> `deserialized` (line 294) [type=deserialization, conf=0.85]
- `key` (line 221) -> `asString` (line 349) [type=deserialization, conf=0.85]
- `key` (line 221) -> `serializedValue` (line 327) [type=deserialization, conf=0.82]
- `noteKey` (line 334) -> `asString` (line 349) [type=deserialization, conf=0.82]
- `this` (line 336) -> `asBytes` (line 246) [type=deserialization, conf=0.85]
- `this` (line 336) -> `deserialized` (line 294) [type=deserialization, conf=0.85]
- `this` (line 336) -> `asString` (line 349) [type=deserialization, conf=0.85]
- `this` (line 336) -> `serializedValue` (line 327) [type=deserialization, conf=0.82]
- `clazz` (line 379) -> `asString` (line 349) [type=deserialization, conf=0.77]

### CVE-2022-3782/RedirectUtils.java
_CVE:_ CVE-2022-3782

- TP: 0 / 0
- FP (matched patterns): 2
- FN: 0
- Unclassified: 4
- Pipeline metrics: {'sources_found': 17, 'sinks_found': 10, 'sanitizers_found': 11, 'chains_found': 15, 'chains_verified': 6, 'verification_rate': 0.4, 'explanations_generated': 6, 'graph_nodes': 248, 'graph_edges': 142}

#### False Positives (matched FP patterns)
- `validRedirects` -> `validRedirect` [type=open_redirect, conf=0.85] — Logging
- `rootUrl` -> `validRedirect` [type=open_redirect, conf=0.77] — Logging

#### Unclassified chains
- `rootUrl` (line 218) -> `redirectUri` (line 151) [type=open_redirect, conf=0.85]
- `rootUrl` (line 218) -> `redirectUri` (line 112) [type=other, conf=0.80]
- `relative` (line 164) -> `redirectUri` (line 151) [type=open_redirect, conf=0.85]
- `relative` (line 164) -> `redirectUri` (line 112) [type=other, conf=0.80]

### CVE-2022-4361/SamlService.java
_CVE:_ CVE-2022-4361

- TP: 0 / 1
- FP (matched patterns): 0
- FN: 1
- Unclassified: 183
- Pipeline metrics: {'sources_found': 90, 'sinks_found': 53, 'sanitizers_found': 3, 'chains_found': 197, 'chains_verified': 183, 'verification_rate': 0.9289340101522843, 'explanations_generated': 183, 'graph_nodes': 1060, 'graph_edges': 1137}

#### False Negatives (expected TPs not found)
- TP-1: `redirectUri` -> `redirect` (getAssertionConsumerServiceURL (deserialized SAML XML) -> authSession.setRedirectUri)

#### Unclassified chains
- `samlRequest` (line 265) -> `issuer` (line 243) [type=sql_injection, conf=0.90]
- `samlRequest` (line 265) -> `relayState` (line 203) [type=ssrf, conf=0.85]
- `samlRequest` (line 265) -> `logoutRelayState` (line 624) [type=other, conf=0.86]
- `samlRequest` (line 265) -> `logoutBindingUri` (line 627) [type=other, conf=0.83]
- `samlRequest` (line 265) -> `soapBodyContents` (line 1048) [type=xxe, conf=0.88]
- `samlRequest` (line 265) -> `clientMessage` (line 1433) [type=xxe, conf=0.85]
- `samlRequest` (line 265) -> `issuer` (line 243) [type=other, conf=0.88]
- `samlRequest` (line 866) -> `authSession` (line 851) [type=open_redirect, conf=0.88]
- `samlRequest` (line 265) -> `artifactResponseString` (line 1194) [type=deserialization, conf=0.85]
- `relayState` (line 341) -> `issuer` (line 243) [type=sql_injection, conf=0.90]
- `relayState` (line 341) -> `logoutRelayState` (line 624) [type=other, conf=0.86]
- `relayState` (line 341) -> `logoutBindingUri` (line 627) [type=other, conf=0.83]
- `relayState` (line 341) -> `soapBodyContents` (line 1048) [type=xxe, conf=0.88]
- `relayState` (line 341) -> `clientMessage` (line 1433) [type=xxe, conf=0.85]
- `relayState` (line 341) -> `issuer` (line 243) [type=other, conf=0.88]
- `relayState` (line 866) -> `authSession` (line 851) [type=open_redirect, conf=0.88]
- `relayState` (line 341) -> `artifactResponseString` (line 1194) [type=deserialization, conf=0.85]
- `issuer` (line 243) -> `relayState` (line 203) [type=ssrf, conf=0.85]
- `issuer` (line 243) -> `logoutRelayState` (line 624) [type=other, conf=0.86]
- `issuer` (line 243) -> `logoutBindingUri` (line 627) [type=other, conf=0.83]
- `issuer` (line 243) -> `soapBodyContents` (line 1048) [type=xxe, conf=0.88]
- `issuer` (line 243) -> `clientMessage` (line 1433) [type=xxe, conf=0.85]
- `issuer` (line 243) -> `client` (line 255) [type=other, conf=0.88]
- `issuer` (line 243) -> `response` (line 788) [type=xxe, conf=0.90]
- `issuer` (line 243) -> `authSession` (line 851) [type=open_redirect, conf=0.88]
- `issuer` (line 243) -> `samlProtocol` (line 852) [type=open_redirect, conf=0.85]
- `artifact` (line 341) -> `issuer` (line 243) [type=sql_injection, conf=0.90]
- `artifact` (line 341) -> `relayState` (line 203) [type=ssrf, conf=0.85]
- `artifact` (line 341) -> `logoutRelayState` (line 624) [type=other, conf=0.86]
- `artifact` (line 341) -> `logoutBindingUri` (line 627) [type=other, conf=0.83]
- `artifact` (line 341) -> `soapBodyContents` (line 1048) [type=xxe, conf=0.88]
- `artifact` (line 341) -> `clientMessage` (line 1433) [type=xxe, conf=0.85]
- `artifact` (line 341) -> `issuer` (line 243) [type=other, conf=0.88]
- `artifact` (line 341) -> `samlProtocol` (line 852) [type=open_redirect, conf=0.85]
- `artifact` (line 866) -> `authSession` (line 851) [type=open_redirect, conf=0.88]
- `artifact` (line 341) -> `artifactResponseString` (line 1194) [type=deserialization, conf=0.85]
- `baseID` (line 486) -> `issuer` (line 243) [type=sql_injection, conf=0.90]
- `baseID` (line 486) -> `relayState` (line 203) [type=ssrf, conf=0.85]
- `baseID` (line 486) -> `logoutRelayState` (line 624) [type=other, conf=0.86]
- `baseID` (line 486) -> `logoutBindingUri` (line 627) [type=other, conf=0.83]
- `baseID` (line 486) -> `soapBodyContents` (line 1048) [type=xxe, conf=0.88]
- `baseID` (line 486) -> `clientMessage` (line 1433) [type=xxe, conf=0.85]
- `baseID` (line 486) -> `issuer` (line 243) [type=other, conf=0.88]
- `baseID` (line 486) -> `client` (line 255) [type=other, conf=0.88]
- `baseID` (line 486) -> `authSession` (line 851) [type=open_redirect, conf=0.88]
- `baseID` (line 486) -> `samlProtocol` (line 852) [type=open_redirect, conf=0.85]
- `baseID` (line 486) -> `artifactResponseString` (line 1194) [type=deserialization, conf=0.85]
- `redirectUri` (line 424) -> `issuer` (line 243) [type=sql_injection, conf=0.85]
- `redirectUri` (line 424) -> `relayState` (line 203) [type=ssrf, conf=0.80]
- `redirectUri` (line 424) -> `logoutRelayState` (line 624) [type=other, conf=0.81]
- `redirectUri` (line 424) -> `logoutBindingUri` (line 627) [type=other, conf=0.78]
- `redirectUri` (line 424) -> `soapBodyContents` (line 1048) [type=xxe, conf=0.82]
- `redirectUri` (line 424) -> `clientMessage` (line 1433) [type=xxe, conf=0.80]
- `redirectUri` (line 424) -> `issuer` (line 243) [type=other, conf=0.82]
- `redirectUri` (line 424) -> `client` (line 255) [type=other, conf=0.82]
- `redirectUri` (line 424) -> `authSession` (line 851) [type=open_redirect, conf=0.82]
- `redirectUri` (line 424) -> `artifactResponseString` (line 1194) [type=deserialization, conf=0.80]
- `logoutRequest` (line 534) -> `issuer` (line 243) [type=sql_injection, conf=0.85]
- `logoutRequest` (line 534) -> `relayState` (line 203) [type=ssrf, conf=0.80]
- `logoutRequest` (line 534) -> `logoutRelayState` (line 624) [type=other, conf=0.81]
- `logoutRequest` (line 534) -> `logoutBindingUri` (line 627) [type=other, conf=0.78]
- `logoutRequest` (line 534) -> `soapBodyContents` (line 1048) [type=xxe, conf=0.82]
- `logoutRequest` (line 534) -> `clientMessage` (line 1433) [type=xxe, conf=0.80]
- `logoutRequest` (line 534) -> `issuer` (line 243) [type=other, conf=0.82]
- `logoutRequest` (line 534) -> `authSession` (line 965) [type=open_redirect, conf=0.80]
- `logoutRequest` (line 534) -> `artifactResponseString` (line 1194) [type=deserialization, conf=0.80]
- `samlResponse` (line 678) -> `issuer` (line 243) [type=sql_injection, conf=0.90]
- `samlResponse` (line 678) -> `relayState` (line 203) [type=ssrf, conf=0.85]
- `samlResponse` (line 678) -> `logoutRelayState` (line 624) [type=other, conf=0.86]
- `samlResponse` (line 678) -> `logoutBindingUri` (line 627) [type=other, conf=0.83]
- `samlResponse` (line 678) -> `soapBodyContents` (line 1048) [type=xxe, conf=0.88]
- `samlResponse` (line 678) -> `clientMessage` (line 1433) [type=xxe, conf=0.85]
- `samlResponse` (line 678) -> `issuer` (line 243) [type=other, conf=0.88]
- `samlResponse` (line 678) -> `samlProtocol` (line 852) [type=open_redirect, conf=0.85]
- `samlResponse` (line 866) -> `authSession` (line 851) [type=open_redirect, conf=0.88]
- `samlRequest` (line 866) -> `client` (line 255) [type=other, conf=0.88]
- `samlRequest` (line 866) -> `response` (line 788) [type=xxe, conf=0.90]
- `samlRequest` (line 866) -> `documentHolder` (line 818) [type=other, conf=0.88]
- `samlResponse` (line 866) -> `client` (line 255) [type=other, conf=0.88]
- `samlResponse` (line 866) -> `response` (line 788) [type=xxe, conf=0.90]
- `relayState` (line 866) -> `client` (line 255) [type=other, conf=0.88]
- `relayState` (line 866) -> `response` (line 788) [type=xxe, conf=0.90]
- `artifact` (line 866) -> `client` (line 255) [type=other, conf=0.88]
- `artifact` (line 866) -> `response` (line 788) [type=xxe, conf=0.90]
- `realm` (line 897) -> `issuer` (line 243) [type=sql_injection, conf=0.85]
- `realm` (line 897) -> `relayState` (line 203) [type=ssrf, conf=0.80]
- `realm` (line 897) -> `soapBodyContents` (line 1048) [type=xxe, conf=0.82]
- `realm` (line 897) -> `clientMessage` (line 1433) [type=xxe, conf=0.80]
- `realm` (line 897) -> `issuer` (line 243) [type=other, conf=0.82]
- `realm` (line 897) -> `samlProtocol` (line 852) [type=open_redirect, conf=0.80]
- `realm` (line 897) -> `authSession` (line 965) [type=open_redirect, conf=0.80]
- `redirect` (line 1017) -> `issuer` (line 243) [type=sql_injection, conf=0.72]
- `redirect` (line 1017) -> `relayState` (line 203) [type=ssrf, conf=0.68]
- `redirect` (line 1017) -> `logoutRelayState` (line 624) [type=other, conf=0.69]
- `redirect` (line 1017) -> `logoutBindingUri` (line 627) [type=other, conf=0.66]
- `redirect` (line 1017) -> `soapBodyContents` (line 1048) [type=xxe, conf=0.70]
- `redirect` (line 1017) -> `clientMessage` (line 1433) [type=xxe, conf=0.68]
- `redirect` (line 1017) -> `issuer` (line 243) [type=other, conf=0.70]
- `redirect` (line 1017) -> `client` (line 255) [type=other, conf=0.70]
- `redirect` (line 1017) -> `authSession` (line 851) [type=open_redirect, conf=0.70]
- `redirect` (line 1017) -> `samlProtocol` (line 852) [type=open_redirect, conf=0.68]
- `redirect` (line 1017) -> `artifactResponseString` (line 1194) [type=deserialization, conf=0.68]
- `clientSessionId` (line 1103) -> `issuer` (line 243) [type=sql_injection, conf=0.85]
- `clientSessionId` (line 1103) -> `relayState` (line 203) [type=ssrf, conf=0.80]
- `clientSessionId` (line 1103) -> `soapBodyContents` (line 1048) [type=xxe, conf=0.82]
- `clientSessionId` (line 1103) -> `clientMessage` (line 1433) [type=xxe, conf=0.80]
- `clientSessionId` (line 1103) -> `issuer` (line 243) [type=other, conf=0.82]
- `clientId` (line 1103) -> `issuer` (line 243) [type=sql_injection, conf=0.85]
- `clientId` (line 1103) -> `relayState` (line 203) [type=ssrf, conf=0.80]
- `clientId` (line 1103) -> `soapBodyContents` (line 1048) [type=xxe, conf=0.82]
- `clientId` (line 1103) -> `clientMessage` (line 1433) [type=xxe, conf=0.80]
- `clientId` (line 1103) -> `issuer` (line 243) [type=other, conf=0.82]
- `artifactResolveMessage` (line 1240) -> `issuer` (line 243) [type=sql_injection, conf=0.88]
- `artifactResolveMessage` (line 1240) -> `artifact` (line 346) [type=xxe, conf=0.88]
- `artifactResolveMessage` (line 1240) -> `relayState` (line 203) [type=ssrf, conf=0.82]
- `artifactResolveMessage` (line 1240) -> `soapBodyContents` (line 1048) [type=xxe, conf=0.85]
- `artifactResolveMessage` (line 1240) -> `clientMessage` (line 1433) [type=xxe, conf=0.82]
- `artifactResolveMessage` (line 1240) -> `issuer` (line 243) [type=other, conf=0.85]
- `artifactResolveMessage` (line 1240) -> `artifactResponseString` (line 1194) [type=deserialization, conf=0.82]
- `clientArtifactBindingURI` (line 383) -> `soapBodyContents` (line 1048) [type=xxe, conf=0.78]
- `clientArtifactBindingURI` (line 383) -> `clientMessage` (line 1433) [type=xxe, conf=0.75]
- `clientArtifactBindingURI` (line 383) -> `response` (line 788) [type=xxe, conf=0.80]
- `soapBodyContents` (line 1048) -> `clientMessage` (line 1433) [type=xxe, conf=0.82]
- `soapBodyContents` (line 1048) -> `response` (line 788) [type=xxe, conf=0.88]
- `documentHolder` (line 405) -> `issuer` (line 243) [type=sql_injection, conf=0.85]
- `documentHolder` (line 405) -> `relayState` (line 203) [type=ssrf, conf=0.80]
- `documentHolder` (line 405) -> `logoutRelayState` (line 624) [type=other, conf=0.81]
- `documentHolder` (line 405) -> `logoutBindingUri` (line 627) [type=other, conf=0.78]
- `documentHolder` (line 405) -> `soapBodyContents` (line 1048) [type=xxe, conf=0.82]
- `documentHolder` (line 405) -> `clientMessage` (line 1433) [type=xxe, conf=0.80]
- `documentHolder` (line 405) -> `issuer` (line 243) [type=other, conf=0.82]
- `documentHolder` (line 815) -> `authSession` (line 851) [type=open_redirect, conf=0.82]
- `documentHolder` (line 405) -> `artifactResponseString` (line 1194) [type=deserialization, conf=0.80]
- `requestedProtocolBinding` (line 509) -> `issuer` (line 243) [type=sql_injection, conf=0.85]
- `requestedProtocolBinding` (line 509) -> `relayState` (line 203) [type=ssrf, conf=0.80]
- `requestedProtocolBinding` (line 509) -> `logoutRelayState` (line 624) [type=other, conf=0.81]
- `requestedProtocolBinding` (line 509) -> `logoutBindingUri` (line 627) [type=other, conf=0.78]
- `requestedProtocolBinding` (line 509) -> `soapBodyContents` (line 1048) [type=xxe, conf=0.82]
- `requestedProtocolBinding` (line 509) -> `clientMessage` (line 1433) [type=xxe, conf=0.80]
- `requestedProtocolBinding` (line 509) -> `issuer` (line 243) [type=other, conf=0.82]
- `requestedProtocolBinding` (line 509) -> `authSession` (line 965) [type=open_redirect, conf=0.80]
- `requestedProtocolBinding` (line 509) -> `artifactResponseString` (line 1194) [type=deserialization, conf=0.80]
- `nameIdFormat` (line 524) -> `issuer` (line 243) [type=sql_injection, conf=0.77]
- `nameIdFormat` (line 524) -> `relayState` (line 203) [type=ssrf, conf=0.72]
- `nameIdFormat` (line 524) -> `logoutRelayState` (line 624) [type=other, conf=0.74]
- `nameIdFormat` (line 524) -> `logoutBindingUri` (line 627) [type=other, conf=0.71]
- `nameIdFormat` (line 524) -> `soapBodyContents` (line 1048) [type=xxe, conf=0.75]
- `nameIdFormat` (line 524) -> `clientMessage` (line 1433) [type=xxe, conf=0.72]
- `nameIdFormat` (line 524) -> `issuer` (line 243) [type=other, conf=0.75]
- `nameIdFormat` (line 524) -> `samlProtocol` (line 852) [type=open_redirect, conf=0.72]
- `nameIdFormat` (line 524) -> `authSession` (line 965) [type=open_redirect, conf=0.72]
- `nameIdFormat` (line 524) -> `artifactResponseString` (line 1194) [type=deserialization, conf=0.72]
- `clientConnection` (line 674) -> `issuer` (line 243) [type=sql_injection, conf=0.77]
- `clientConnection` (line 674) -> `relayState` (line 203) [type=ssrf, conf=0.72]
- `clientConnection` (line 674) -> `logoutRelayState` (line 624) [type=other, conf=0.74]
- `clientConnection` (line 674) -> `soapBodyContents` (line 1048) [type=xxe, conf=0.75]
- `clientConnection` (line 674) -> `clientMessage` (line 1433) [type=xxe, conf=0.72]
- `clientConnection` (line 674) -> `issuer` (line 243) [type=other, conf=0.75]
- `clientConnection` (line 674) -> `client` (line 255) [type=other, conf=0.75]
- `clientConnection` (line 674) -> `response` (line 788) [type=xxe, conf=0.77]
- `clientConnection` (line 674) -> `authSession` (line 851) [type=open_redirect, conf=0.75]
- `clientConnection` (line 674) -> `samlProtocol` (line 852) [type=open_redirect, conf=0.72]
- `documentHolder` (line 815) -> `client` (line 255) [type=other, conf=0.82]
- `authSession` (line 851) -> `issuer` (line 243) [type=sql_injection, conf=0.85]
- `authSession` (line 851) -> `relayState` (line 203) [type=ssrf, conf=0.80]
- `authSession` (line 851) -> `logoutRelayState` (line 624) [type=other, conf=0.81]
- `authSession` (line 851) -> `logoutBindingUri` (line 627) [type=other, conf=0.78]
- `authSession` (line 851) -> `soapBodyContents` (line 1048) [type=xxe, conf=0.82]
- `authSession` (line 851) -> `clientMessage` (line 1433) [type=xxe, conf=0.80]
- `authSession` (line 851) -> `issuer` (line 243) [type=other, conf=0.82]
- `authSession` (line 851) -> `samlProtocol` (line 852) [type=open_redirect, conf=0.80]
- `authSession` (line 851) -> `artifactResponseString` (line 1194) [type=deserialization, conf=0.80]
- `clientUrlName` (line 943) -> `issuer` (line 243) [type=sql_injection, conf=0.90]
- `clientUrlName` (line 943) -> `relayState` (line 203) [type=ssrf, conf=0.85]
- `clientUrlName` (line 943) -> `soapBodyContents` (line 1048) [type=xxe, conf=0.88]
- `clientUrlName` (line 943) -> `clientMessage` (line 1433) [type=xxe, conf=0.85]
- `clientUrlName` (line 943) -> `issuer` (line 243) [type=other, conf=0.88]
- `clientUrlName` (line 943) -> `client` (line 255) [type=other, conf=0.88]
- `clientUrlName` (line 943) -> `response` (line 788) [type=xxe, conf=0.90]
- `clientUrlName` (line 943) -> `authSession` (line 851) [type=open_redirect, conf=0.88]
- `inputStream` (line 1040) -> `soapBodyContents` (line 1048) [type=xxe, conf=0.88]
- `inputStream` (line 1040) -> `clientMessage` (line 1433) [type=xxe, conf=0.85]
- `inputStream` (line 1040) -> `response` (line 788) [type=xxe, conf=0.90]
