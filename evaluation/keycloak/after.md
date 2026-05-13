# VTC Evaluation Report

## Aggregate metrics

| Metric | Value |
|--------|-------|
| Files analyzed | 4 |
| Files failed | 0 |
| True positives | 2 / 8 expected |
| False positives | 17 (matched FP patterns) |
| False negatives | 6 |
| Unclassified | 294 |
| Precision (TP / TP+FP) | 10.53% |
| Precision strict (TP / TP+FP+Uncl) | 0.64% |
| Recall | 25.00% |
| F1 | 0.1481 |

## Per-file breakdown

### OIDCLoginProtocol.java
_CVE:_ CVE-2024-2419

- TP: 0 / 3
- FP (matched patterns): 5
- FN: 3
- Unclassified: 1
- Pipeline metrics: {'sources_found': 14, 'sinks_found': 5, 'sanitizers_found': 3, 'chains_found': 8, 'chains_verified': 6, 'verification_rate': 0.75, 'explanations_generated': 6, 'graph_nodes': 486, 'graph_edges': 393}

#### False Positives (matched FP patterns)
- `authSession` -> `redirectUri` [type=xss, conf=0.70] — Server-controlled framework values
- `authSession` -> `token` [type=command_injection, conf=0.70] — Server-controlled framework values
- `clientSession` -> `redirectUri` [type=xss, conf=0.70] — Server-controlled framework values
- `clientSession` -> `client` [type=xss, conf=0.70] — Server-controlled framework values
- `userSession` -> `redirectUri` [type=xss, conf=0.70] — Framework setter field

#### False Negatives (expected TPs not found)
- TP-1: `redirect` -> `redirectUri` (authSession.getRedirectUri() -> redirectUri.build() in authenticated())
- TP-2: `redirect` -> `redirectUri` (authSession.getRedirectUri() -> redirectUri.build() in sendError())
- TP-3: `redirectUri` -> `finalRedirectUri` (logoutSession.getAuthNote(LOGOUT_REDIRECT_URI) -> renderLogoutPage())

#### Unclassified chains
- `codeData` (line 241) -> `redirectUri` (line 235) [type=xss, conf=0.70]

### SerializedBrokeredIdentityContext.java
_CVE:_ internal (Unsafe Deserialization patterns)

- TP: 1 / 4
- FP (matched patterns): 0
- FN: 3
- Unclassified: 12
- Pipeline metrics: {'sources_found': 32, 'sinks_found': 12, 'sanitizers_found': 1, 'chains_found': 27, 'chains_verified': 13, 'verification_rate': 0.48148148148148145, 'explanations_generated': 13, 'graph_nodes': 265, 'graph_edges': 172}

#### True Positives matched
- `asString` (line 349) -> `serializedCtx` (line 351) [type=deserialization, conf=0.90] == expected TP-3 (authSession.getAuthNote() -> JsonSerialization.readValue())

#### False Negatives (expected TPs not found)
- TP-1: `value` -> `clazz` (value.getClazz() -> Reflections.classForName())
- TP-2: `value` -> `ctxData` (value.getData() -> serializer.deserialize())
- TP-4: `ctxEntry` -> `asBytes` (ctxEntry.getData() -> JsonSerialization.readValue())

#### Unclassified chains
- `value` (line 215) -> `ctxEntry` (line 244) [type=deserialization, conf=0.80]
- `value` (line 215) -> `serializedCtx` (line 351) [type=deserialization, conf=0.80]
- `value` (line 223) -> `attrs` (line 262) [type=xss, conf=0.70]
- `key` (line 241) -> `ctxEntry` (line 244) [type=deserialization, conf=0.90]
- `key` (line 241) -> `serializedCtx` (line 351) [type=deserialization, conf=0.90]
- `name` (line 258) -> `attrs` (line 262) [type=xss, conf=0.70]
- `authSession` (line 278) -> `ctxEntry` (line 244) [type=deserialization, conf=0.80]
- `authSession` (line 278) -> `serializedCtx` (line 351) [type=deserialization, conf=0.80]
- `getIdentityProviderId` (line 179) -> `ctxEntry` (line 244) [type=deserialization, conf=0.80]
- `getIdentityProviderId` (line 179) -> `serializedCtx` (line 351) [type=deserialization, conf=0.80]
- `noteKey` (line 337) -> `serializedCtx` (line 351) [type=deserialization, conf=0.80]
- `asString` (line 349) -> `ctxEntry` (line 244) [type=deserialization, conf=0.90]

### CVE-2022-3782/RedirectUtils.java
_CVE:_ CVE-2022-3782

- TP: 0 / 0
- FP (matched patterns): 0
- FN: 0
- Unclassified: 0
- Pipeline metrics: {'sources_found': 0, 'sinks_found': 0, 'sanitizers_found': 11, 'chains_found': 0, 'chains_verified': 0, 'verification_rate': 0.0, 'explanations_generated': 0, 'graph_nodes': 243, 'graph_edges': 128}

### CVE-2022-4361/SamlService.java
_CVE:_ CVE-2022-4361

- TP: 1 / 1
- FP (matched patterns): 12
- FN: 0
- Unclassified: 281
- Pipeline metrics: {'sources_found': 63, 'sinks_found': 55, 'sanitizers_found': 3, 'chains_found': 323, 'chains_verified': 294, 'verification_rate': 0.9102167182662538, 'explanations_generated': 294, 'graph_nodes': 1043, 'graph_edges': 1137}

#### True Positives matched
- `redirectUri` (line 424) -> `redirect` (line 171) [type=xss, conf=0.70] == expected TP-1 (getAssertionConsumerServiceURL (deserialized SAML XML) -> authSession.setRedirectUri)

#### False Positives (matched FP patterns)
- `samlRequest` -> `postUrl` [type=xss, conf=0.70] — Internal client config
- `issuerNameId` -> `postUrl` [type=xss, conf=0.70] — Internal client config
- `artifact` -> `postUrl` [type=xss, conf=0.70] — Internal client config
- `requestAbstractType` -> `postUrl` [type=xss, conf=0.70] — Internal client config
- `client` -> `postUrl` [type=xss, conf=0.70] — Internal client config
- `logoutRequest` -> `postUrl` [type=xss, conf=0.70] — Internal client config
- `clientSession` -> `postUrl` [type=xss, conf=0.70] — Internal client config
- `samlResponse` -> `postUrl` [type=xss, conf=0.70] — Internal client config
- `realm` -> `postUrl` [type=xss, conf=0.70] — Internal client config
- `clientModel` -> `postUrl` [type=xss, conf=0.70] — Internal client config
- `issuer` -> `postUrl` [type=xss, conf=0.70] — Internal client config
- `bindingType` -> `postUrl` [type=xss, conf=0.70] — Internal client config

#### Unclassified chains
- `samlRequest` (line 177) -> `samlClient` (line 303) [type=sql_injection, conf=0.70]
- `samlRequest` (line 177) -> `doc` (line 375) [type=sql_injection, conf=0.70]
- `samlRequest` (line 177) -> `nameIdFormat` (line 468) [type=sql_injection, conf=0.70]
- `samlRequest` (line 177) -> `redirect` (line 171) [type=xss, conf=0.70]
- `samlRequest` (line 177) -> `asyncReponse` (line 698) [type=xss, conf=0.70]
- `samlRequest` (line 177) -> `asyncResponse` (line 870) [type=sql_injection, conf=0.70]
- `samlRequest` (line 177) -> `asyncResponse` (line 870) [type=command_injection, conf=0.70]
- `samlRequest` (line 177) -> `asyncResponse` (line 870) [type=path_traversal, conf=0.70]
- `samlRequest` (line 177) -> `asyncResponse` (line 870) [type=xxe, conf=0.70]
- `samlRequest` (line 177) -> `asyncResponse` (line 870) [type=ssrf, conf=0.70]
- `samlRequest` (line 177) -> `postBindingProtocol` (line 885) [type=sql_injection, conf=0.70]
- `samlRequest` (line 177) -> `signingKeys` (line 919) [type=sql_injection, conf=0.70]
- `samlRequest` (line 177) -> `IDPMetadataDescriptor` (line 893) [type=xss, conf=0.70]
- `samlRequest` (line 177) -> `getUrl` (line 983) [type=xss, conf=0.70]
- `samlRequest` (line 177) -> `client` (line 1106) [type=sql_injection, conf=0.70]
- `samlRequest` (line 177) -> `artifactResponseDocument` (line 1252) [type=xss, conf=0.70]
- `samlRequest` (line 177) -> `bindingBuilder` (line 1290) [type=xss, conf=0.70]
- `samlRequest` (line 177) -> `messageBuilder` (line 1296) [type=xss, conf=0.70]
- `samlRequest` (line 177) -> `artifactResolve` (line 1331) [type=sql_injection, conf=0.70]
- `samlRequest` (line 177) -> `samlDoc` (line 403) [type=sql_injection, conf=0.70]
- `samlRequest` (line 177) -> `clientMessage` (line 1433) [type=xxe, conf=0.70]
- `samlRequest` (line 177) -> `clientMessage` (line 1434) [type=ssrf, conf=0.70]
- `relayState` (line 203) -> `asyncReponse` (line 698) [type=xss, conf=0.70]
- `relayState` (line 203) -> `postBindingProtocol` (line 885) [type=sql_injection, conf=0.70]
- `issuerNameId` (line 290) -> `samlClient` (line 303) [type=sql_injection, conf=0.70]
- `issuerNameId` (line 290) -> `doc` (line 375) [type=sql_injection, conf=0.70]
- `issuerNameId` (line 290) -> `redirect` (line 171) [type=xss, conf=0.70]
- `issuerNameId` (line 290) -> `asyncReponse` (line 698) [type=xss, conf=0.70]
- `issuerNameId` (line 290) -> `asyncResponse` (line 870) [type=sql_injection, conf=0.70]
- `issuerNameId` (line 290) -> `asyncResponse` (line 870) [type=command_injection, conf=0.70]
- `issuerNameId` (line 290) -> `asyncResponse` (line 870) [type=path_traversal, conf=0.70]
- `issuerNameId` (line 290) -> `asyncResponse` (line 870) [type=xxe, conf=0.70]
- `issuerNameId` (line 290) -> `asyncResponse` (line 870) [type=ssrf, conf=0.70]
- `issuerNameId` (line 290) -> `postBindingProtocol` (line 885) [type=sql_injection, conf=0.70]
- `issuerNameId` (line 290) -> `signingKeys` (line 919) [type=sql_injection, conf=0.70]
- `issuerNameId` (line 290) -> `IDPMetadataDescriptor` (line 893) [type=xss, conf=0.70]
- `issuerNameId` (line 290) -> `getUrl` (line 983) [type=xss, conf=0.70]
- `issuerNameId` (line 290) -> `client` (line 1106) [type=sql_injection, conf=0.70]
- `issuerNameId` (line 290) -> `artifactResponseDocument` (line 1252) [type=xss, conf=0.70]
- `issuerNameId` (line 290) -> `bindingBuilder` (line 1290) [type=xss, conf=0.70]
- `issuerNameId` (line 290) -> `messageBuilder` (line 1296) [type=xss, conf=0.70]
- `issuerNameId` (line 290) -> `artifactResolve` (line 1331) [type=sql_injection, conf=0.70]
- `issuerNameId` (line 290) -> `samlDoc` (line 403) [type=sql_injection, conf=0.70]
- `issuerNameId` (line 290) -> `clientMessage` (line 1433) [type=xxe, conf=0.70]
- `issuerNameId` (line 290) -> `clientMessage` (line 1434) [type=ssrf, conf=0.70]
- `artifact` (line 346) -> `samlClient` (line 303) [type=sql_injection, conf=0.70]
- `artifact` (line 346) -> `doc` (line 375) [type=sql_injection, conf=0.70]
- `artifact` (line 346) -> `redirect` (line 171) [type=xss, conf=0.70]
- `artifact` (line 346) -> `asyncReponse` (line 698) [type=xss, conf=0.70]
- `artifact` (line 346) -> `asyncResponse` (line 870) [type=sql_injection, conf=0.70]
- `artifact` (line 346) -> `asyncResponse` (line 870) [type=command_injection, conf=0.70]
- `artifact` (line 346) -> `asyncResponse` (line 870) [type=path_traversal, conf=0.70]
- `artifact` (line 346) -> `asyncResponse` (line 870) [type=xxe, conf=0.70]
- `artifact` (line 346) -> `asyncResponse` (line 870) [type=ssrf, conf=0.70]
- `artifact` (line 346) -> `postBindingProtocol` (line 885) [type=sql_injection, conf=0.70]
- `artifact` (line 346) -> `signingKeys` (line 919) [type=sql_injection, conf=0.70]
- `artifact` (line 346) -> `IDPMetadataDescriptor` (line 893) [type=xss, conf=0.70]
- `artifact` (line 346) -> `getUrl` (line 983) [type=xss, conf=0.70]
- `artifact` (line 346) -> `client` (line 1106) [type=sql_injection, conf=0.70]
- `artifact` (line 346) -> `bindingBuilder` (line 1290) [type=xss, conf=0.70]
- `artifact` (line 346) -> `messageBuilder` (line 1296) [type=xss, conf=0.70]
- `artifact` (line 346) -> `artifactResolve` (line 1331) [type=sql_injection, conf=0.70]
- `artifact` (line 346) -> `samlDoc` (line 403) [type=sql_injection, conf=0.70]
- `artifact` (line 346) -> `clientMessage` (line 1433) [type=xxe, conf=0.70]
- `artifact` (line 346) -> `clientMessage` (line 1434) [type=ssrf, conf=0.70]
- `clientArtifactBindingURL` (line 377) -> `asyncReponse` (line 698) [type=xss, conf=0.70]
- `clientArtifactBindingURL` (line 377) -> `artifactResponseDocument` (line 1252) [type=xss, conf=0.70]
- `clientArtifactBindingURL` (line 377) -> `bindingBuilder` (line 1290) [type=xss, conf=0.70]
- `clientArtifactBindingURL` (line 377) -> `messageBuilder` (line 1296) [type=xss, conf=0.70]
- `clientArtifactBindingURL` (line 377) -> `artifactResolve` (line 1331) [type=sql_injection, conf=0.70]
- `clientArtifactBindingURL` (line 377) -> `samlDoc` (line 403) [type=sql_injection, conf=0.70]
- `clientArtifactBindingURL` (line 377) -> `clientMessage` (line 1433) [type=xxe, conf=0.70]
- `clientArtifactBindingURL` (line 377) -> `clientMessage` (line 1434) [type=ssrf, conf=0.70]
- `requestAbstractType` (line 430) -> `samlClient` (line 303) [type=sql_injection, conf=0.70]
- `requestAbstractType` (line 430) -> `doc` (line 375) [type=sql_injection, conf=0.70]
- `requestAbstractType` (line 430) -> `nameIdFormat` (line 468) [type=sql_injection, conf=0.70]
- `requestAbstractType` (line 430) -> `redirect` (line 171) [type=xss, conf=0.70]
- `requestAbstractType` (line 430) -> `asyncReponse` (line 698) [type=xss, conf=0.70]
- `requestAbstractType` (line 430) -> `asyncResponse` (line 870) [type=sql_injection, conf=0.63]
- `requestAbstractType` (line 430) -> `asyncResponse` (line 870) [type=command_injection, conf=0.63]
- `requestAbstractType` (line 430) -> `asyncResponse` (line 870) [type=path_traversal, conf=0.63]
- `requestAbstractType` (line 430) -> `asyncResponse` (line 870) [type=xxe, conf=0.63]
- `requestAbstractType` (line 430) -> `asyncResponse` (line 870) [type=ssrf, conf=0.63]
- `requestAbstractType` (line 430) -> `postBindingProtocol` (line 885) [type=sql_injection, conf=0.63]
- `requestAbstractType` (line 430) -> `signingKeys` (line 919) [type=sql_injection, conf=0.70]
- `requestAbstractType` (line 430) -> `IDPMetadataDescriptor` (line 893) [type=xss, conf=0.70]
- `requestAbstractType` (line 430) -> `getUrl` (line 983) [type=xss, conf=0.70]
- `requestAbstractType` (line 430) -> `client` (line 1106) [type=sql_injection, conf=0.70]
- `requestAbstractType` (line 430) -> `artifactResponseDocument` (line 1252) [type=xss, conf=0.70]
- `requestAbstractType` (line 430) -> `bindingBuilder` (line 1290) [type=xss, conf=0.70]
- `requestAbstractType` (line 430) -> `messageBuilder` (line 1296) [type=xss, conf=0.70]
- `requestAbstractType` (line 430) -> `artifactResolve` (line 1331) [type=sql_injection, conf=0.70]
- `requestAbstractType` (line 430) -> `samlDoc` (line 403) [type=sql_injection, conf=0.70]
- `requestAbstractType` (line 430) -> `clientMessage` (line 1433) [type=xxe, conf=0.70]
- `requestAbstractType` (line 430) -> `clientMessage` (line 1434) [type=ssrf, conf=0.70]
- `client` (line 436) -> `samlClient` (line 303) [type=sql_injection, conf=0.70]
- `client` (line 436) -> `doc` (line 375) [type=sql_injection, conf=0.70]
- `client` (line 436) -> `redirect` (line 171) [type=xss, conf=0.70]
- `client` (line 436) -> `asyncReponse` (line 698) [type=xss, conf=0.70]
- `client` (line 436) -> `signingKeys` (line 919) [type=sql_injection, conf=0.70]
- `client` (line 436) -> `IDPMetadataDescriptor` (line 893) [type=xss, conf=0.70]
- `client` (line 436) -> `getUrl` (line 983) [type=xss, conf=0.70]
- `client` (line 436) -> `artifactResponseDocument` (line 1252) [type=xss, conf=0.70]
- `client` (line 436) -> `bindingBuilder` (line 1290) [type=xss, conf=0.70]
- `client` (line 436) -> `messageBuilder` (line 1296) [type=xss, conf=0.70]
- `client` (line 436) -> `samlDoc` (line 403) [type=sql_injection, conf=0.70]
- `client` (line 436) -> `clientMessage` (line 1433) [type=xxe, conf=0.70]
- `client` (line 436) -> `clientMessage` (line 1434) [type=ssrf, conf=0.70]
- `nameIdPolicy` (line 467) -> `nameIdFormat` (line 468) [type=sql_injection, conf=0.70]
- `logoutRequest` (line 559) -> `samlClient` (line 303) [type=sql_injection, conf=0.70]
- `logoutRequest` (line 559) -> `doc` (line 375) [type=sql_injection, conf=0.70]
- `logoutRequest` (line 559) -> `redirect` (line 171) [type=xss, conf=0.70]
- `logoutRequest` (line 559) -> `asyncResponse` (line 870) [type=sql_injection, conf=0.70]
- `logoutRequest` (line 559) -> `asyncResponse` (line 870) [type=command_injection, conf=0.70]
- `logoutRequest` (line 559) -> `asyncResponse` (line 870) [type=path_traversal, conf=0.70]
- `logoutRequest` (line 559) -> `asyncResponse` (line 870) [type=xxe, conf=0.70]
- `logoutRequest` (line 559) -> `asyncResponse` (line 870) [type=ssrf, conf=0.70]
- `logoutRequest` (line 559) -> `postBindingProtocol` (line 885) [type=sql_injection, conf=0.70]
- `logoutRequest` (line 559) -> `signingKeys` (line 919) [type=sql_injection, conf=0.70]
- `logoutRequest` (line 559) -> `IDPMetadataDescriptor` (line 893) [type=xss, conf=0.70]
- `logoutRequest` (line 559) -> `getUrl` (line 983) [type=xss, conf=0.70]
- `logoutRequest` (line 559) -> `client` (line 1106) [type=sql_injection, conf=0.70]
- `logoutRequest` (line 559) -> `artifactResponseDocument` (line 1252) [type=xss, conf=0.70]
- `logoutRequest` (line 559) -> `bindingBuilder` (line 1290) [type=xss, conf=0.70]
- `logoutRequest` (line 559) -> `messageBuilder` (line 1296) [type=xss, conf=0.70]
- `logoutRequest` (line 559) -> `artifactResolve` (line 1331) [type=sql_injection, conf=0.70]
- `logoutRequest` (line 559) -> `samlDoc` (line 403) [type=sql_injection, conf=0.70]
- `logoutRequest` (line 559) -> `clientMessage` (line 1433) [type=xxe, conf=0.70]
- `logoutRequest` (line 559) -> `clientMessage` (line 1434) [type=ssrf, conf=0.70]
- `clientSession` (line 574) -> `samlClient` (line 303) [type=sql_injection, conf=0.70]
- `clientSession` (line 574) -> `doc` (line 375) [type=sql_injection, conf=0.70]
- `clientSession` (line 574) -> `redirect` (line 171) [type=xss, conf=0.70]
- `clientSession` (line 574) -> `signingKeys` (line 919) [type=sql_injection, conf=0.70]
- `clientSession` (line 574) -> `IDPMetadataDescriptor` (line 893) [type=xss, conf=0.70]
- `clientSession` (line 574) -> `getUrl` (line 983) [type=xss, conf=0.70]
- `clientSession` (line 574) -> `client` (line 1106) [type=sql_injection, conf=0.70]
- `clientSession` (line 574) -> `artifactResponseDocument` (line 1252) [type=xss, conf=0.70]
- `clientSession` (line 574) -> `bindingBuilder` (line 1290) [type=xss, conf=0.70]
- `clientSession` (line 574) -> `messageBuilder` (line 1296) [type=xss, conf=0.70]
- `clientSession` (line 574) -> `samlDoc` (line 403) [type=sql_injection, conf=0.70]
- `clientSession` (line 574) -> `clientMessage` (line 1433) [type=xxe, conf=0.70]
- `clientSession` (line 574) -> `clientMessage` (line 1434) [type=ssrf, conf=0.70]
- `samlClient` (line 301) -> `bindingBuilder` (line 1290) [type=xss, conf=0.70]
- `samlResponse` (line 177) -> `samlClient` (line 303) [type=sql_injection, conf=0.70]
- `samlResponse` (line 177) -> `doc` (line 375) [type=sql_injection, conf=0.70]
- `samlResponse` (line 177) -> `redirect` (line 171) [type=xss, conf=0.70]
- `samlResponse` (line 177) -> `asyncReponse` (line 698) [type=xss, conf=0.70]
- `samlResponse` (line 177) -> `asyncResponse` (line 870) [type=sql_injection, conf=0.70]
- `samlResponse` (line 177) -> `asyncResponse` (line 870) [type=command_injection, conf=0.70]
- `samlResponse` (line 177) -> `asyncResponse` (line 870) [type=path_traversal, conf=0.70]
- `samlResponse` (line 177) -> `asyncResponse` (line 870) [type=xxe, conf=0.70]
- `samlResponse` (line 177) -> `asyncResponse` (line 870) [type=ssrf, conf=0.70]
- `samlResponse` (line 177) -> `postBindingProtocol` (line 885) [type=sql_injection, conf=0.70]
- `samlResponse` (line 177) -> `signingKeys` (line 919) [type=sql_injection, conf=0.70]
- `samlResponse` (line 177) -> `IDPMetadataDescriptor` (line 893) [type=xss, conf=0.70]
- `samlResponse` (line 177) -> `getUrl` (line 983) [type=xss, conf=0.70]
- `samlResponse` (line 177) -> `client` (line 1106) [type=sql_injection, conf=0.70]
- `samlResponse` (line 177) -> `artifactResponseDocument` (line 1252) [type=xss, conf=0.70]
- `samlResponse` (line 177) -> `bindingBuilder` (line 1290) [type=xss, conf=0.70]
- `samlResponse` (line 177) -> `messageBuilder` (line 1296) [type=xss, conf=0.70]
- `samlResponse` (line 177) -> `artifactResolve` (line 1331) [type=sql_injection, conf=0.70]
- `samlResponse` (line 177) -> `samlDoc` (line 403) [type=sql_injection, conf=0.70]
- `samlResponse` (line 177) -> `clientMessage` (line 1433) [type=xxe, conf=0.70]
- `samlResponse` (line 177) -> `clientMessage` (line 1434) [type=ssrf, conf=0.70]
- `samlDocument` (line 763) -> `artifactResponseDocument` (line 1252) [type=xss, conf=0.70]
- `samlDocument` (line 763) -> `bindingBuilder` (line 1290) [type=xss, conf=0.70]
- `samlDocument` (line 763) -> `messageBuilder` (line 1296) [type=xss, conf=0.70]
- `uriInfo` (line 823) -> `signingKeys` (line 919) [type=sql_injection, conf=0.70]
- `uriInfo` (line 823) -> `IDPMetadataDescriptor` (line 893) [type=xss, conf=0.70]
- `uriInfo` (line 823) -> `artifactResponseDocument` (line 1252) [type=xss, conf=0.70]
- `uriInfo` (line 823) -> `messageBuilder` (line 1296) [type=xss, conf=0.70]
- `realm` (line 912) -> `samlClient` (line 303) [type=sql_injection, conf=0.70]
- `realm` (line 912) -> `doc` (line 375) [type=sql_injection, conf=0.70]
- `realm` (line 912) -> `redirect` (line 171) [type=xss, conf=0.70]
- `realm` (line 912) -> `signingKeys` (line 919) [type=sql_injection, conf=0.70]
- `realm` (line 912) -> `IDPMetadataDescriptor` (line 893) [type=xss, conf=0.70]
- `realm` (line 912) -> `getUrl` (line 983) [type=xss, conf=0.70]
- `realm` (line 912) -> `client` (line 1106) [type=sql_injection, conf=0.70]
- `realm` (line 912) -> `artifactResponseDocument` (line 1252) [type=xss, conf=0.70]
- `realm` (line 912) -> `bindingBuilder` (line 1290) [type=xss, conf=0.70]
- `realm` (line 912) -> `messageBuilder` (line 1296) [type=xss, conf=0.70]
- `realm` (line 912) -> `samlDoc` (line 403) [type=sql_injection, conf=0.70]
- `realm` (line 912) -> `clientMessage` (line 1433) [type=xxe, conf=0.70]
- `realm` (line 912) -> `clientMessage` (line 1434) [type=ssrf, conf=0.70]
- `client` (line 989) -> `artifactResolve` (line 1331) [type=sql_injection, conf=0.70]
- `clientSessionId` (line 1104) -> `samlClient` (line 303) [type=sql_injection, conf=0.70]
- `clientSessionId` (line 1104) -> `doc` (line 375) [type=sql_injection, conf=0.70]
- `clientSessionId` (line 1104) -> `client` (line 1106) [type=sql_injection, conf=0.70]
- `clientSessionId` (line 1104) -> `bindingBuilder` (line 1290) [type=xss, conf=0.70]
- `clientSessionId` (line 1104) -> `messageBuilder` (line 1296) [type=xss, conf=0.70]
- `clientSessionId` (line 1104) -> `artifactResolve` (line 1331) [type=sql_injection, conf=0.70]
- `clientSessionId` (line 1104) -> `samlDoc` (line 403) [type=sql_injection, conf=0.70]
- `clientSessionId` (line 1104) -> `clientMessage` (line 1433) [type=xxe, conf=0.70]
- `clientSessionId` (line 1104) -> `clientMessage` (line 1434) [type=ssrf, conf=0.70]
- `clientId` (line 1103) -> `samlClient` (line 303) [type=sql_injection, conf=0.70]
- `clientId` (line 1103) -> `doc` (line 375) [type=sql_injection, conf=0.70]
- `clientId` (line 1103) -> `client` (line 1106) [type=sql_injection, conf=0.70]
- `clientId` (line 1103) -> `artifactResponseDocument` (line 1252) [type=xss, conf=0.70]
- `clientId` (line 1103) -> `bindingBuilder` (line 1290) [type=xss, conf=0.70]
- `clientId` (line 1103) -> `messageBuilder` (line 1296) [type=xss, conf=0.70]
- `clientId` (line 1103) -> `artifactResolve` (line 1331) [type=sql_injection, conf=0.70]
- `clientId` (line 1103) -> `samlDoc` (line 403) [type=sql_injection, conf=0.70]
- `clientId` (line 1103) -> `clientMessage` (line 1433) [type=xxe, conf=0.70]
- `clientId` (line 1103) -> `clientMessage` (line 1434) [type=ssrf, conf=0.70]
- `artifactResolveMessage` (line 1252) -> `samlClient` (line 303) [type=sql_injection, conf=0.70]
- `artifactResolveMessage` (line 1252) -> `doc` (line 375) [type=sql_injection, conf=0.70]
- `artifactResolveMessage` (line 1252) -> `client` (line 1106) [type=sql_injection, conf=0.70]
- `artifactResolveMessage` (line 1252) -> `artifactResponseDocument` (line 1252) [type=xss, conf=0.70]
- `artifactResolveMessage` (line 1252) -> `bindingBuilder` (line 1290) [type=xss, conf=0.70]
- `artifactResolveMessage` (line 1252) -> `messageBuilder` (line 1296) [type=xss, conf=0.70]
- `artifactResolveMessage` (line 1252) -> `artifactResolve` (line 1331) [type=sql_injection, conf=0.70]
- `artifactResolveMessage` (line 1252) -> `samlDoc` (line 403) [type=sql_injection, conf=0.70]
- `artifactResolveMessage` (line 1252) -> `clientMessage` (line 1433) [type=xxe, conf=0.70]
- `artifactResolveMessage` (line 1252) -> `clientMessage` (line 1434) [type=ssrf, conf=0.70]
- `clientModel` (line 1252) -> `samlClient` (line 303) [type=sql_injection, conf=0.70]
- `clientModel` (line 1252) -> `doc` (line 375) [type=sql_injection, conf=0.70]
- `clientModel` (line 1252) -> `redirect` (line 171) [type=xss, conf=0.70]
- `clientModel` (line 1252) -> `signingKeys` (line 919) [type=sql_injection, conf=0.70]
- `clientModel` (line 1252) -> `IDPMetadataDescriptor` (line 893) [type=xss, conf=0.70]
- `clientModel` (line 1252) -> `getUrl` (line 983) [type=xss, conf=0.70]
- `clientModel` (line 1252) -> `client` (line 1106) [type=sql_injection, conf=0.70]
- `clientModel` (line 1252) -> `artifactResponseDocument` (line 1252) [type=xss, conf=0.70]
- `clientModel` (line 1252) -> `bindingBuilder` (line 1290) [type=xss, conf=0.70]
- `clientModel` (line 1252) -> `messageBuilder` (line 1296) [type=xss, conf=0.70]
- `clientModel` (line 1252) -> `samlDoc` (line 403) [type=sql_injection, conf=0.70]
- `clientModel` (line 1252) -> `clientMessage` (line 1433) [type=xxe, conf=0.70]
- `clientModel` (line 1252) -> `clientMessage` (line 1434) [type=ssrf, conf=0.70]
- `responseStatusCode` (line 1240) -> `artifactResponseDocument` (line 1252) [type=xss, conf=0.70]
- `responseStatusCode` (line 1240) -> `bindingBuilder` (line 1290) [type=xss, conf=0.70]
- `responseStatusCode` (line 1240) -> `messageBuilder` (line 1296) [type=xss, conf=0.70]
- `artifactResponseDocument` (line 1207) -> `bindingBuilder` (line 1290) [type=xss, conf=0.70]
- `artifactResponseDocument` (line 1207) -> `messageBuilder` (line 1296) [type=xss, conf=0.70]
- `issuer` (line 1320) -> `samlClient` (line 303) [type=sql_injection, conf=0.70]
- `issuer` (line 1320) -> `doc` (line 375) [type=sql_injection, conf=0.70]
- `issuer` (line 1320) -> `redirect` (line 171) [type=xss, conf=0.70]
- `issuer` (line 1320) -> `asyncReponse` (line 698) [type=xss, conf=0.70]
- `issuer` (line 1320) -> `signingKeys` (line 919) [type=sql_injection, conf=0.70]
- `issuer` (line 1320) -> `IDPMetadataDescriptor` (line 893) [type=xss, conf=0.70]
- `issuer` (line 1320) -> `getUrl` (line 983) [type=xss, conf=0.70]
- `issuer` (line 1320) -> `client` (line 1106) [type=sql_injection, conf=0.70]
- `issuer` (line 1320) -> `artifactResponseDocument` (line 1252) [type=xss, conf=0.70]
- `issuer` (line 1320) -> `bindingBuilder` (line 1290) [type=xss, conf=0.70]
- `issuer` (line 1320) -> `messageBuilder` (line 1296) [type=xss, conf=0.70]
- `issuer` (line 1320) -> `artifactResolve` (line 1331) [type=sql_injection, conf=0.70]
- `issuer` (line 1320) -> `samlDoc` (line 403) [type=sql_injection, conf=0.70]
- `issuer` (line 1320) -> `clientMessage` (line 1433) [type=xxe, conf=0.70]
- `issuer` (line 1320) -> `clientMessage` (line 1434) [type=ssrf, conf=0.70]
- `realmId` (line 1344) -> `doc` (line 375) [type=sql_injection, conf=0.70]
- `realmId` (line 1344) -> `messageBuilder` (line 1296) [type=xss, conf=0.70]
- `realmId` (line 1344) -> `samlDoc` (line 403) [type=sql_injection, conf=0.70]
- `realmId` (line 1344) -> `clientMessage` (line 1433) [type=xxe, conf=0.70]
- `realmId` (line 1344) -> `clientMessage` (line 1434) [type=ssrf, conf=0.70]
- `clientArtifactBindingURI` (line 383) -> `asyncReponse` (line 698) [type=xss, conf=0.70]
- `clientArtifactBindingURI` (line 383) -> `artifactResponseDocument` (line 1252) [type=xss, conf=0.70]
- `clientArtifactBindingURI` (line 383) -> `bindingBuilder` (line 1290) [type=xss, conf=0.70]
- `clientArtifactBindingURI` (line 383) -> `messageBuilder` (line 1296) [type=xss, conf=0.70]
- `clientArtifactBindingURI` (line 383) -> `artifactResolve` (line 1331) [type=sql_injection, conf=0.70]
- `clientArtifactBindingURI` (line 383) -> `samlDoc` (line 403) [type=sql_injection, conf=0.70]
- `clientArtifactBindingURI` (line 383) -> `clientMessage` (line 1433) [type=xxe, conf=0.70]
- `clientArtifactBindingURI` (line 383) -> `clientMessage` (line 1434) [type=ssrf, conf=0.70]
- `bindingType` (line 420) -> `samlClient` (line 303) [type=sql_injection, conf=0.70]
- `bindingType` (line 420) -> `doc` (line 375) [type=sql_injection, conf=0.70]
- `bindingType` (line 420) -> `redirect` (line 171) [type=xss, conf=0.70]
- `bindingType` (line 420) -> `asyncReponse` (line 698) [type=xss, conf=0.70]
- `bindingType` (line 420) -> `signingKeys` (line 919) [type=sql_injection, conf=0.70]
- `bindingType` (line 420) -> `IDPMetadataDescriptor` (line 893) [type=xss, conf=0.70]
- `bindingType` (line 420) -> `getUrl` (line 983) [type=xss, conf=0.70]
- `bindingType` (line 420) -> `client` (line 1106) [type=sql_injection, conf=0.70]
- `bindingType` (line 420) -> `artifactResponseDocument` (line 1252) [type=xss, conf=0.70]
- `bindingType` (line 420) -> `messageBuilder` (line 1296) [type=xss, conf=0.70]
- `bindingType` (line 420) -> `samlDoc` (line 403) [type=sql_injection, conf=0.70]
- `bindingType` (line 420) -> `clientMessage` (line 1433) [type=xxe, conf=0.70]
- `bindingType` (line 420) -> `clientMessage` (line 1434) [type=ssrf, conf=0.70]
- `doc` (line 266) -> `asyncReponse` (line 698) [type=xss, conf=0.70]
- `doc` (line 266) -> `artifactResponseDocument` (line 1252) [type=xss, conf=0.70]
- `doc` (line 266) -> `bindingBuilder` (line 1290) [type=xss, conf=0.70]
- `doc` (line 266) -> `messageBuilder` (line 1296) [type=xss, conf=0.70]
- `doc` (line 266) -> `artifactResolve` (line 1331) [type=sql_injection, conf=0.70]
- `doc` (line 266) -> `samlDoc` (line 403) [type=sql_injection, conf=0.70]
- `doc` (line 266) -> `clientMessage` (line 1433) [type=xxe, conf=0.70]
- `doc` (line 266) -> `clientMessage` (line 1434) [type=ssrf, conf=0.70]
