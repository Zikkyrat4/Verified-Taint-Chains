# VTC Evaluation Report

## Aggregate metrics

| Metric | Value |
|--------|-------|
| Files analyzed | 7 |
| Files failed | 0 |
| True positives | 1 / 10 expected |
| False positives | 4 (matched FP patterns) |
| False negatives | 10 |
| Unclassified | 330 |
| Precision (TP / TP+FP) | 20.00% |
| Precision strict (TP / TP+FP+Uncl) | 0.30% |
| Recall | 9.09% |
| F1 | 0.1250 |

## Per-file breakdown

### OIDCLoginProtocol.java
_CVE:_ CVE-2024-2419

- TP: 0 / 3
- FP (matched patterns): 0
- FN: 3
- Unclassified: 6
- Pipeline metrics: {'sources_found': 17, 'sinks_found': 12, 'sanitizers_found': 4, 'chains_found': 6, 'chains_verified': 6, 'verification_rate': 1.0, 'explanations_generated': 6, 'graph_nodes': 492, 'graph_edges': 392}

#### False Negatives (expected TPs not found)
- TP-1: `redirect` -> `redirectUri` (authSession.getRedirectUri() -> redirectUri.build() in authenticated())
- TP-2: `redirect` -> `redirectUri` (authSession.getRedirectUri() -> redirectUri.build() in sendError())
- TP-3: `redirectUri` -> `finalRedirectUri` (logoutSession.getAuthNote(LOGOUT_REDIRECT_URI) -> renderLogoutPage())

#### Unclassified chains
- `resource` (line 460) -> `token` (line 466) [type=command_injection, conf=0.70]
- `resource` (line 460) -> `status` (line 468) [type=ssrf, conf=0.70]
- `notBefore` (line 462) -> `token` (line 466) [type=command_injection, conf=0.70]
- `notBefore` (line 462) -> `status` (line 468) [type=ssrf, conf=0.70]
- `managementUrl` (line 462) -> `token` (line 466) [type=command_injection, conf=0.70]
- `managementUrl` (line 462) -> `status` (line 468) [type=ssrf, conf=0.70]

### SerializedBrokeredIdentityContext.java
_CVE:_ internal (Unsafe Deserialization patterns)

- TP: 0 / 4
- FP (matched patterns): 0
- FN: 4
- Unclassified: 4
- Pipeline metrics: {'sources_found': 32, 'sinks_found': 12, 'sanitizers_found': 4, 'chains_found': 6, 'chains_verified': 4, 'verification_rate': 0.6666666666666666, 'explanations_generated': 4, 'graph_nodes': 265, 'graph_edges': 162}

#### False Negatives (expected TPs not found)
- TP-1: `value` -> `clazz` (value.getClazz() -> Reflections.classForName())
- TP-2: `value` -> `ctxData` (value.getData() -> serializer.deserialize())
- TP-3: `asString` -> `ctx` (authSession.getAuthNote() -> JsonSerialization.readValue())
- TP-4: `ctxEntry` -> `asBytes` (ctxEntry.getData() -> JsonSerialization.readValue())

#### Unclassified chains
- `key` (line 244) -> `ctxEntry` (line 249) [type=sql_injection, conf=0.90]
- `name` (line 259) -> `attrs` (line 262) [type=xss, conf=0.70]
- `authSession` (line 338) -> `asString` (line 338) [type=xss, conf=0.70]
- `asString` (line 349) -> `serializedCtx` (line 356) [type=sql_injection, conf=0.90]

### CVE-2014-3656/RealmsResource.java
_CVE:_ CVE-2014-3656

- TP: 0 / 1
- FP (matched patterns): 4
- FN: 1
- Unclassified: 1
- Pipeline metrics: {'sources_found': 5, 'sinks_found': 4, 'sanitizers_found': 0, 'chains_found': 5, 'chains_verified': 5, 'verification_rate': 1.0, 'explanations_generated': 5, 'graph_nodes': 158, 'graph_edges': 60}

#### False Positives (matched FP patterns)
- `name` -> `accountService` [type=xss, conf=0.70] — Validated against allowlist
- `client_id` -> `accountService` [type=xss, conf=0.70] — Validated against allowlist
- `name` -> `realm` [type=sql_injection, conf=0.70] — Validated against allowlist
- `name` -> `accountService` [type=xss, conf=0.70] — Validated against allowlist

#### False Negatives (expected TPs not found)
- TP-1: `origin` -> `file` (@QueryParam origin -> file.replace -> Response.ok)

#### Unclassified chains
- `origin` (line 119) -> `file` (line 132) [type=xss, conf=0.70]

### CVE-2022-1274/UserResource.java
_CVE:_ CVE-2022-1274

- TP: 0 / 1
- FP (matched patterns): 0
- FN: 1
- Unclassified: 98
- Pipeline metrics: {'sources_found': 23, 'sinks_found': 26, 'sanitizers_found': 6, 'chains_found': 186, 'chains_verified': 98, 'verification_rate': 0.5268817204301075, 'explanations_generated': 98, 'graph_nodes': 755, 'graph_edges': 545}

#### False Negatives (expected TPs not found)
- TP-1: `redirectUri` -> `token` (@QueryParam redirectUri -> ExecuteActionsActionToken constructor -> email body)

#### Unclassified chains
- `rep` (line 173) -> `profile` (line 191) [type=sql_injection, conf=0.70]
- `rep` (line 173) -> `profile` (line 195) [type=xss, conf=0.70]
- `clientId` (line 528) -> `realm` (line 390) [type=sql_injection, conf=0.82]
- `clientId` (line 528) -> `user` (line 390) [type=xss, conf=0.82]
- `clientId` (line 528) -> `user` (line 623) [type=xss, conf=0.82]
- `clientId` (line 528) -> `credential` (line 688) [type=sql_injection, conf=0.70]
- `clientId` (line 528) -> `credential` (line 692) [type=xss, conf=0.70]
- `clientId` (line 528) -> `credential` (line 739) [type=sql_injection, conf=0.70]
- `clientId` (line 528) -> `link` (line 816) [type=xss, conf=0.70]
- `clientId` (line 528) -> `link` (line 823) [type=xss, conf=0.70]
- `cred` (line 615) -> `user` (line 390) [type=xss, conf=0.95]
- `cred` (line 615) -> `user` (line 623) [type=xss, conf=0.95]
- `cred` (line 615) -> `credential` (line 688) [type=sql_injection, conf=0.82]
- `cred` (line 615) -> `credential` (line 692) [type=xss, conf=0.82]
- `cred` (line 615) -> `credential` (line 739) [type=sql_injection, conf=0.82]
- `cred` (line 615) -> `link` (line 816) [type=xss, conf=0.82]
- `cred` (line 615) -> `link` (line 823) [type=xss, conf=0.82]
- `cred` (line 615) -> `group` (line 933) [type=sql_injection, conf=0.82]
- `cred` (line 615) -> `group` (line 948) [type=xss, conf=0.82]
- `credentialId` (line 684) -> `user` (line 390) [type=xss, conf=0.82]
- `credentialId` (line 684) -> `user` (line 623) [type=xss, conf=0.82]
- `credentialId` (line 684) -> `credential` (line 688) [type=sql_injection, conf=0.70]
- `credentialId` (line 684) -> `credential` (line 692) [type=xss, conf=0.70]
- `credentialId` (line 684) -> `credential` (line 739) [type=sql_injection, conf=0.70]
- `credentialId` (line 684) -> `link` (line 816) [type=xss, conf=0.70]
- `credentialId` (line 684) -> `link` (line 823) [type=xss, conf=0.70]
- `credentialId` (line 684) -> `group` (line 933) [type=sql_injection, conf=0.70]
- `credentialId` (line 684) -> `group` (line 948) [type=xss, conf=0.70]
- `credentialId` (line 702) -> `credential` (line 706) [type=sql_injection, conf=0.70]
- `userLabel` (line 703) -> `credential` (line 706) [type=sql_injection, conf=0.70]
- `credentialId` (line 731) -> `user` (line 390) [type=xss, conf=0.82]
- `credentialId` (line 731) -> `user` (line 623) [type=xss, conf=0.82]
- `credentialId` (line 731) -> `credential` (line 688) [type=sql_injection, conf=0.70]
- `credentialId` (line 731) -> `credential` (line 692) [type=xss, conf=0.70]
- `credentialId` (line 731) -> `credential` (line 739) [type=sql_injection, conf=0.70]
- `credentialId` (line 731) -> `link` (line 816) [type=xss, conf=0.70]
- `credentialId` (line 731) -> `link` (line 823) [type=xss, conf=0.70]
- `credentialId` (line 731) -> `group` (line 933) [type=sql_injection, conf=0.70]
- `credentialId` (line 731) -> `group` (line 948) [type=xss, conf=0.70]
- `newPreviousCredentialId` (line 732) -> `user` (line 390) [type=xss, conf=0.82]
- `newPreviousCredentialId` (line 732) -> `user` (line 623) [type=xss, conf=0.82]
- `newPreviousCredentialId` (line 732) -> `credential` (line 688) [type=sql_injection, conf=0.70]
- `newPreviousCredentialId` (line 732) -> `credential` (line 692) [type=xss, conf=0.70]
- `newPreviousCredentialId` (line 732) -> `credential` (line 739) [type=sql_injection, conf=0.70]
- `newPreviousCredentialId` (line 732) -> `link` (line 816) [type=xss, conf=0.70]
- `newPreviousCredentialId` (line 732) -> `link` (line 823) [type=xss, conf=0.70]
- `newPreviousCredentialId` (line 732) -> `group` (line 933) [type=sql_injection, conf=0.70]
- `newPreviousCredentialId` (line 732) -> `group` (line 948) [type=xss, conf=0.70]
- `redirectUri` (line 801) -> `user` (line 390) [type=xss, conf=0.82]
- `redirectUri` (line 801) -> `user` (line 623) [type=xss, conf=0.82]
- `redirectUri` (line 801) -> `credential` (line 688) [type=sql_injection, conf=0.70]
- `redirectUri` (line 801) -> `credential` (line 692) [type=xss, conf=0.70]
- `redirectUri` (line 801) -> `credential` (line 739) [type=sql_injection, conf=0.70]
- `redirectUri` (line 801) -> `link` (line 816) [type=xss, conf=0.70]
- `redirectUri` (line 801) -> `link` (line 823) [type=xss, conf=0.70]
- `redirectUri` (line 801) -> `group` (line 933) [type=sql_injection, conf=0.70]
- `redirectUri` (line 801) -> `group` (line 948) [type=xss, conf=0.70]
- `clientId` (line 802) -> `realm` (line 390) [type=sql_injection, conf=0.82]
- `clientId` (line 802) -> `user` (line 390) [type=xss, conf=0.82]
- `clientId` (line 802) -> `user` (line 623) [type=xss, conf=0.82]
- `clientId` (line 802) -> `credential` (line 688) [type=sql_injection, conf=0.70]
- `clientId` (line 802) -> `credential` (line 692) [type=xss, conf=0.70]
- `clientId` (line 802) -> `credential` (line 739) [type=sql_injection, conf=0.70]
- `clientId` (line 802) -> `link` (line 816) [type=xss, conf=0.70]
- `clientId` (line 802) -> `link` (line 823) [type=xss, conf=0.70]
- `lifespan` (line 803) -> `user` (line 390) [type=xss, conf=0.82]
- `lifespan` (line 803) -> `user` (line 623) [type=xss, conf=0.82]
- `lifespan` (line 803) -> `link` (line 816) [type=xss, conf=0.70]
- `lifespan` (line 803) -> `link` (line 823) [type=xss, conf=0.70]
- `lifespan` (line 803) -> `group` (line 933) [type=sql_injection, conf=0.70]
- `lifespan` (line 803) -> `group` (line 948) [type=xss, conf=0.70]
- `actions` (line 804) -> `user` (line 390) [type=xss, conf=0.82]
- `actions` (line 804) -> `user` (line 623) [type=xss, conf=0.82]
- `actions` (line 804) -> `credential` (line 688) [type=sql_injection, conf=0.70]
- `actions` (line 804) -> `credential` (line 692) [type=xss, conf=0.70]
- `actions` (line 804) -> `credential` (line 739) [type=sql_injection, conf=0.70]
- `actions` (line 804) -> `link` (line 816) [type=xss, conf=0.70]
- `actions` (line 804) -> `link` (line 823) [type=xss, conf=0.70]
- `actions` (line 804) -> `group` (line 933) [type=sql_injection, conf=0.70]
- `actions` (line 804) -> `group` (line 948) [type=xss, conf=0.70]
- `clientId` (line 809) -> `realm` (line 390) [type=sql_injection, conf=0.82]
- `clientId` (line 809) -> `user` (line 390) [type=xss, conf=0.82]
- `clientId` (line 809) -> `user` (line 623) [type=xss, conf=0.82]
- `clientId` (line 809) -> `credential` (line 688) [type=sql_injection, conf=0.70]
- `clientId` (line 809) -> `credential` (line 692) [type=xss, conf=0.70]
- `clientId` (line 809) -> `credential` (line 739) [type=sql_injection, conf=0.70]
- `clientId` (line 809) -> `link` (line 816) [type=xss, conf=0.70]
- `clientId` (line 809) -> `link` (line 823) [type=xss, conf=0.70]
- `groupId` (line 920) -> `user` (line 390) [type=xss, conf=0.82]
- `groupId` (line 920) -> `user` (line 623) [type=xss, conf=0.82]
- `groupId` (line 920) -> `group` (line 933) [type=sql_injection, conf=0.70]
- `groupId` (line 920) -> `group` (line 948) [type=xss, conf=0.70]
- `group` (line 924) -> `user` (line 390) [type=xss, conf=0.82]
- `group` (line 924) -> `user` (line 623) [type=xss, conf=0.82]
- `groupId` (line 941) -> `user` (line 390) [type=xss, conf=0.82]
- `groupId` (line 941) -> `user` (line 623) [type=xss, conf=0.82]
- `groupId` (line 941) -> `group` (line 933) [type=sql_injection, conf=0.70]
- `groupId` (line 941) -> `group` (line 948) [type=xss, conf=0.70]

### CVE-2022-3782/RedirectUtils.java
_CVE:_ CVE-2022-3782

- TP: 0 / 0
- FP (matched patterns): 0
- FN: 0
- Unclassified: 0
- Pipeline metrics: {'sources_found': 0, 'sinks_found': 0, 'sanitizers_found': 12, 'chains_found': 0, 'chains_verified': 0, 'verification_rate': 0.0, 'explanations_generated': 0, 'graph_nodes': 243, 'graph_edges': 125}

### CVE-2022-4137/OAuth2Error.java
_CVE:_ CVE-2022-4137

- TP: 1 / 0
- FP (matched patterns): 0
- FN: 0
- Unclassified: 1
- Pipeline metrics: {'sources_found': 15, 'sinks_found': 18, 'sanitizers_found': 1, 'chains_found': 2, 'chains_verified': 2, 'verification_rate': 1.0, 'explanations_generated': 2, 'graph_nodes': 239, 'graph_edges': 139}

#### True Positives matched
- `errorDescription` (line 134) -> `error` (line 133) [type=xss, conf=0.70] == expected TP-1 (errorDescription -> OAuth2ErrorRepresentation -> Response (rendered to client))

#### Unclassified chains
- `challenge` (line 187) -> `master` (line 189) [type=xss, conf=0.70]

### CVE-2022-4361/SamlService.java
_CVE:_ CVE-2022-4361

- TP: 0 / 1
- FP (matched patterns): 0
- FN: 1
- Unclassified: 220
- Pipeline metrics: {'sources_found': 63, 'sinks_found': 55, 'sanitizers_found': 11, 'chains_found': 227, 'chains_verified': 220, 'verification_rate': 0.9691629955947136, 'explanations_generated': 185, 'graph_nodes': 1043, 'graph_edges': 1137}

#### False Negatives (expected TPs not found)
- TP-1: `redirectUri` -> `redirect` (getAssertionConsumerServiceURL (deserialized SAML XML) -> authSession.setRedirectUri)

#### Unclassified chains
- `samlRequest` (line 274) -> `client` (line 298) [type=xss, conf=0.70]
- `samlRequest` (line 274) -> `samlClient` (line 306) [type=sql_injection, conf=0.70]
- `relayState` (line 276) -> `client` (line 298) [type=xss, conf=0.70]
- `relayState` (line 276) -> `samlClient` (line 306) [type=sql_injection, conf=0.70]
- `issuerNameId` (line 285) -> `client` (line 298) [type=xss, conf=0.70]
- `issuerNameId` (line 285) -> `samlClient` (line 306) [type=sql_injection, conf=0.70]
- `artifact` (line 350) -> `doc` (line 374) [type=sql_injection, conf=0.70]
- `artifact` (line 350) -> `doc` (line 382) [type=xxe, conf=0.70]
- `artifact` (line 350) -> `asyncResponse` (line 389) [type=xss, conf=0.70]
- `relayState` (line 353) -> `doc` (line 374) [type=sql_injection, conf=0.70]
- `relayState` (line 353) -> `doc` (line 382) [type=xxe, conf=0.70]
- `relayState` (line 353) -> `asyncResponse` (line 389) [type=xss, conf=0.70]
- `relayState` (line 425) -> `authSession` (line 466) [type=xss, conf=0.70]
- `relayState` (line 425) -> `authSession` (line 474) [type=xss, conf=0.70]
- `relayState` (line 425) -> `nameIdFormat` (line 481) [type=sql_injection, conf=0.70]
- `relayState` (line 425) -> `redirect` (line 493) [type=xss, conf=0.70]
- `requestAbstractType` (line 433) -> `authSession` (line 466) [type=xss, conf=0.70]
- `requestAbstractType` (line 433) -> `authSession` (line 474) [type=xss, conf=0.70]
- `requestAbstractType` (line 433) -> `nameIdFormat` (line 481) [type=sql_injection, conf=0.70]
- `requestAbstractType` (line 433) -> `redirect` (line 493) [type=xss, conf=0.70]
- `client` (line 436) -> `authSession` (line 466) [type=xss, conf=0.70]
- `client` (line 436) -> `authSession` (line 474) [type=xss, conf=0.70]
- `client` (line 436) -> `nameIdFormat` (line 481) [type=sql_injection, conf=0.70]
- `client` (line 436) -> `redirect` (line 493) [type=xss, conf=0.70]
- `redirectUri` (line 443) -> `authSession` (line 466) [type=xss, conf=0.70]
- `redirectUri` (line 443) -> `authSession` (line 474) [type=xss, conf=0.70]
- `redirectUri` (line 443) -> `nameIdFormat` (line 481) [type=sql_injection, conf=0.70]
- `redirectUri` (line 443) -> `redirect` (line 493) [type=xss, conf=0.70]
- `nameIdPolicy` (line 453) -> `authSession` (line 466) [type=xss, conf=0.70]
- `nameIdPolicy` (line 453) -> `authSession` (line 474) [type=xss, conf=0.70]
- `nameIdPolicy` (line 453) -> `nameIdFormat` (line 481) [type=sql_injection, conf=0.70]
- `nameIdPolicy` (line 453) -> `redirect` (line 493) [type=xss, conf=0.70]
- `subject` (line 458) -> `authSession` (line 466) [type=xss, conf=0.70]
- `subject` (line 458) -> `authSession` (line 474) [type=xss, conf=0.70]
- `subject` (line 458) -> `nameIdFormat` (line 481) [type=sql_injection, conf=0.70]
- `subject` (line 458) -> `redirect` (line 493) [type=xss, conf=0.70]
- `logoutRequest` (line 564) -> `response` (line 657) [type=xss, conf=0.70]
- `logoutRequest` (line 564) -> `response` (line 665) [type=xss, conf=0.70]
- `logoutRequest` (line 564) -> `response` (line 672) [type=xss, conf=0.70]
- `logoutRequest` (line 564) -> `response` (line 679) [type=xss, conf=0.70]
- `logoutRequest` (line 564) -> `response` (line 686) [type=xss, conf=0.70]
- `logoutRequest` (line 564) -> `response` (line 693) [type=xss, conf=0.70]
- `logoutRequest` (line 564) -> `response` (line 700) [type=xss, conf=0.70]
- `logoutRequest` (line 564) -> `response` (line 707) [type=xss, conf=0.70]
- `logoutRequest` (line 564) -> `response` (line 714) [type=xss, conf=0.70]
- `logoutRequest` (line 564) -> `response` (line 721) [type=xss, conf=0.70]
- `relayState` (line 568) -> `response` (line 657) [type=xss, conf=0.70]
- `relayState` (line 568) -> `response` (line 665) [type=xss, conf=0.70]
- `relayState` (line 568) -> `response` (line 672) [type=xss, conf=0.70]
- `relayState` (line 568) -> `response` (line 679) [type=xss, conf=0.70]
- `relayState` (line 568) -> `response` (line 686) [type=xss, conf=0.70]
- `relayState` (line 568) -> `response` (line 693) [type=xss, conf=0.70]
- `relayState` (line 568) -> `response` (line 700) [type=xss, conf=0.70]
- `relayState` (line 568) -> `response` (line 707) [type=xss, conf=0.70]
- `relayState` (line 568) -> `response` (line 714) [type=xss, conf=0.70]
- `relayState` (line 568) -> `response` (line 721) [type=xss, conf=0.70]
- `clientSession` (line 574) -> `response` (line 657) [type=xss, conf=0.70]
- `clientSession` (line 574) -> `response` (line 665) [type=xss, conf=0.70]
- `clientSession` (line 574) -> `response` (line 672) [type=xss, conf=0.70]
- `clientSession` (line 574) -> `response` (line 679) [type=xss, conf=0.70]
- `clientSession` (line 574) -> `response` (line 686) [type=xss, conf=0.70]
- `clientSession` (line 574) -> `response` (line 693) [type=xss, conf=0.70]
- `clientSession` (line 574) -> `response` (line 700) [type=xss, conf=0.70]
- `clientSession` (line 574) -> `response` (line 707) [type=xss, conf=0.70]
- `clientSession` (line 574) -> `response` (line 714) [type=xss, conf=0.70]
- `clientSession` (line 574) -> `response` (line 721) [type=xss, conf=0.70]
- `logoutRequest` (line 584) -> `response` (line 657) [type=xss, conf=0.70]
- `logoutRequest` (line 584) -> `response` (line 665) [type=xss, conf=0.70]
- `logoutRequest` (line 584) -> `response` (line 672) [type=xss, conf=0.70]
- `logoutRequest` (line 584) -> `response` (line 679) [type=xss, conf=0.70]
- `logoutRequest` (line 584) -> `response` (line 686) [type=xss, conf=0.70]
- `logoutRequest` (line 584) -> `response` (line 693) [type=xss, conf=0.70]
- `logoutRequest` (line 584) -> `response` (line 700) [type=xss, conf=0.70]
- `logoutRequest` (line 584) -> `response` (line 707) [type=xss, conf=0.70]
- `logoutRequest` (line 584) -> `response` (line 714) [type=xss, conf=0.70]
- `logoutRequest` (line 584) -> `response` (line 721) [type=xss, conf=0.70]
- `clientSession` (line 589) -> `response` (line 657) [type=xss, conf=0.70]
- `clientSession` (line 589) -> `response` (line 665) [type=xss, conf=0.70]
- `clientSession` (line 589) -> `response` (line 672) [type=xss, conf=0.70]
- `clientSession` (line 589) -> `response` (line 679) [type=xss, conf=0.70]
- `clientSession` (line 589) -> `response` (line 686) [type=xss, conf=0.70]
- `clientSession` (line 589) -> `response` (line 693) [type=xss, conf=0.70]
- `clientSession` (line 589) -> `response` (line 700) [type=xss, conf=0.70]
- `clientSession` (line 589) -> `response` (line 707) [type=xss, conf=0.70]
- `clientSession` (line 589) -> `response` (line 714) [type=xss, conf=0.70]
- `clientSession` (line 589) -> `response` (line 721) [type=xss, conf=0.70]
- `logoutRequest` (line 594) -> `response` (line 657) [type=xss, conf=0.70]
- `logoutRequest` (line 594) -> `response` (line 665) [type=xss, conf=0.70]
- `logoutRequest` (line 594) -> `response` (line 672) [type=xss, conf=0.70]
- `logoutRequest` (line 594) -> `response` (line 679) [type=xss, conf=0.70]
- `logoutRequest` (line 594) -> `response` (line 686) [type=xss, conf=0.70]
- `logoutRequest` (line 594) -> `response` (line 693) [type=xss, conf=0.70]
- `logoutRequest` (line 594) -> `response` (line 700) [type=xss, conf=0.70]
- `logoutRequest` (line 594) -> `response` (line 707) [type=xss, conf=0.70]
- `logoutRequest` (line 594) -> `response` (line 714) [type=xss, conf=0.70]
- `logoutRequest` (line 594) -> `response` (line 721) [type=xss, conf=0.70]
- `samlClient` (line 601) -> `response` (line 657) [type=xss, conf=0.70]
- `samlClient` (line 601) -> `response` (line 665) [type=xss, conf=0.70]
- `samlClient` (line 601) -> `response` (line 672) [type=xss, conf=0.70]
- `samlClient` (line 601) -> `response` (line 679) [type=xss, conf=0.70]
- `samlClient` (line 601) -> `response` (line 686) [type=xss, conf=0.70]
- `samlClient` (line 601) -> `response` (line 693) [type=xss, conf=0.70]
- `samlClient` (line 601) -> `response` (line 700) [type=xss, conf=0.70]
- `samlClient` (line 601) -> `response` (line 707) [type=xss, conf=0.70]
- `samlClient` (line 601) -> `response` (line 714) [type=xss, conf=0.70]
- `samlClient` (line 601) -> `response` (line 721) [type=xss, conf=0.70]
- `samlResponse` (line 614) -> `response` (line 657) [type=xss, conf=0.70]
- `samlResponse` (line 614) -> `response` (line 665) [type=xss, conf=0.70]
- `samlResponse` (line 614) -> `response` (line 672) [type=xss, conf=0.70]
- `samlResponse` (line 614) -> `response` (line 679) [type=xss, conf=0.70]
- `samlResponse` (line 614) -> `response` (line 686) [type=xss, conf=0.70]
- `samlResponse` (line 614) -> `response` (line 693) [type=xss, conf=0.70]
- `samlResponse` (line 614) -> `response` (line 700) [type=xss, conf=0.70]
- `samlResponse` (line 614) -> `response` (line 707) [type=xss, conf=0.70]
- `samlResponse` (line 614) -> `response` (line 714) [type=xss, conf=0.70]
- `samlResponse` (line 614) -> `response` (line 721) [type=xss, conf=0.70]
- `samlResponse` (line 624) -> `response` (line 657) [type=xss, conf=0.70]
- `samlResponse` (line 624) -> `response` (line 665) [type=xss, conf=0.70]
- `samlResponse` (line 624) -> `response` (line 672) [type=xss, conf=0.70]
- `samlResponse` (line 624) -> `response` (line 679) [type=xss, conf=0.70]
- `samlResponse` (line 624) -> `response` (line 686) [type=xss, conf=0.70]
- `samlResponse` (line 624) -> `response` (line 693) [type=xss, conf=0.70]
- `samlResponse` (line 624) -> `response` (line 700) [type=xss, conf=0.70]
- `samlResponse` (line 624) -> `response` (line 707) [type=xss, conf=0.70]
- `samlResponse` (line 624) -> `response` (line 714) [type=xss, conf=0.70]
- `samlResponse` (line 624) -> `response` (line 721) [type=xss, conf=0.70]
- `samlRequest` (line 681) -> `response` (line 685) [type=xss, conf=0.70]
- `samlRequest` (line 681) -> `asyncReponse` (line 696) [type=xss, conf=0.70]
- `samlResponse` (line 682) -> `response` (line 685) [type=xss, conf=0.70]
- `samlResponse` (line 682) -> `asyncReponse` (line 696) [type=xss, conf=0.70]
- `relayState` (line 683) -> `response` (line 685) [type=xss, conf=0.70]
- `relayState` (line 683) -> `asyncReponse` (line 696) [type=xss, conf=0.70]
- `artifact` (line 684) -> `response` (line 685) [type=xss, conf=0.70]
- `artifact` (line 684) -> `asyncReponse` (line 696) [type=xss, conf=0.70]
- `samlRequest` (line 693) -> `response` (line 685) [type=xss, conf=0.70]
- `samlRequest` (line 693) -> `asyncReponse` (line 696) [type=xss, conf=0.70]
- `samlResponse` (line 693) -> `response` (line 685) [type=xss, conf=0.70]
- `samlResponse` (line 693) -> `asyncReponse` (line 696) [type=xss, conf=0.70]
- `relayState` (line 693) -> `response` (line 685) [type=xss, conf=0.70]
- `relayState` (line 693) -> `asyncReponse` (line 696) [type=xss, conf=0.70]
- `artifact` (line 693) -> `response` (line 685) [type=xss, conf=0.70]
- `artifact` (line 693) -> `asyncReponse` (line 696) [type=xss, conf=0.70]
- `samlRequest` (line 874) -> `asyncResponse` (line 868) [type=sql_injection, conf=0.70]
- `samlRequest` (line 874) -> `asyncResponse` (line 868) [type=xss, conf=0.70]
- `samlRequest` (line 874) -> `asyncResponse` (line 868) [type=command_injection, conf=0.70]
- `samlRequest` (line 874) -> `asyncResponse` (line 868) [type=path_traversal, conf=0.70]
- `samlRequest` (line 874) -> `asyncResponse` (line 868) [type=xxe, conf=0.70]
- `samlRequest` (line 874) -> `asyncResponse` (line 868) [type=ssrf, conf=0.70]
- `samlResponse` (line 875) -> `asyncResponse` (line 868) [type=sql_injection, conf=0.70]
- `samlResponse` (line 875) -> `asyncResponse` (line 868) [type=xss, conf=0.70]
- `samlResponse` (line 875) -> `asyncResponse` (line 868) [type=command_injection, conf=0.70]
- `samlResponse` (line 875) -> `asyncResponse` (line 868) [type=path_traversal, conf=0.70]
- `samlResponse` (line 875) -> `asyncResponse` (line 868) [type=xxe, conf=0.70]
- `samlResponse` (line 875) -> `asyncResponse` (line 868) [type=ssrf, conf=0.70]
- `relayState` (line 876) -> `asyncResponse` (line 868) [type=sql_injection, conf=0.70]
- `relayState` (line 876) -> `asyncResponse` (line 868) [type=xss, conf=0.70]
- `relayState` (line 876) -> `asyncResponse` (line 868) [type=command_injection, conf=0.70]
- `relayState` (line 876) -> `asyncResponse` (line 868) [type=path_traversal, conf=0.70]
- `relayState` (line 876) -> `asyncResponse` (line 868) [type=xxe, conf=0.70]
- `relayState` (line 876) -> `asyncResponse` (line 868) [type=ssrf, conf=0.70]
- `artifact` (line 877) -> `asyncResponse` (line 868) [type=sql_injection, conf=0.70]
- `artifact` (line 877) -> `asyncResponse` (line 868) [type=xss, conf=0.70]
- `artifact` (line 877) -> `asyncResponse` (line 868) [type=command_injection, conf=0.70]
- `artifact` (line 877) -> `asyncResponse` (line 868) [type=path_traversal, conf=0.70]
- `artifact` (line 877) -> `asyncResponse` (line 868) [type=xxe, conf=0.70]
- `artifact` (line 877) -> `asyncResponse` (line 868) [type=ssrf, conf=0.70]
- `samlRequest` (line 884) -> `postBindingProtocol` (line 889) [type=sql_injection, conf=0.70]
- `samlResponse` (line 885) -> `postBindingProtocol` (line 889) [type=sql_injection, conf=0.70]
- `relayState` (line 886) -> `postBindingProtocol` (line 889) [type=sql_injection, conf=0.70]
- `artifact` (line 887) -> `postBindingProtocol` (line 889) [type=sql_injection, conf=0.70]
- `client` (line 987) -> `postUrl` (line 994) [type=xss, conf=0.70]
- `client` (line 987) -> `postUrl` (line 1000) [type=xss, conf=0.70]
- `client` (line 987) -> `getUrl` (line 1003) [type=xss, conf=0.70]
- `clientSessionId` (line 1106) -> `client` (line 1105) [type=sql_injection, conf=0.70]
- `clientId` (line 1107) -> `client` (line 1105) [type=sql_injection, conf=0.70]
- `artifactResolveMessage` (line 1249) -> `artifactResponseDocument` (line 1253) [type=xss, conf=0.70]
- `clientModel` (line 1249) -> `artifactResponseDocument` (line 1253) [type=xss, conf=0.70]
- `artifactResolveMessage` (line 1264) -> `bindingBuilder` (line 1285) [type=xss, conf=0.70]
- `artifactResolveMessage` (line 1264) -> `messageBuilder` (line 1290) [type=xss, conf=0.70]
- `clientModel` (line 1268) -> `bindingBuilder` (line 1285) [type=xss, conf=0.70]
- `clientModel` (line 1268) -> `messageBuilder` (line 1290) [type=xss, conf=0.70]
- `artifactResponseDocument` (line 1275) -> `bindingBuilder` (line 1285) [type=xss, conf=0.70]
- `artifactResponseDocument` (line 1275) -> `messageBuilder` (line 1290) [type=xss, conf=0.70]
- `artifact` (line 1325) -> `artifactResolve` (line 1331) [type=sql_injection, conf=0.70]
- `artifact` (line 1325) -> `nameIDType` (line 1333) [type=xss, conf=0.70]
- `realmId` (line 1392) -> `response` (line 1422) [type=xss, conf=0.70]
- `realmId` (line 1392) -> `response` (line 1424) [type=xss, conf=0.70]
- `realmId` (line 1392) -> `response` (line 1426) [type=xss, conf=0.70]
- `realmId` (line 1392) -> `samlDoc` (line 1430) [type=sql_injection, conf=0.70]
- `realmId` (line 1392) -> `clientMessage` (line 1432) [type=xxe, conf=0.70]
- `realmId` (line 1392) -> `clientMessage` (line 1434) [type=ssrf, conf=0.70]
- `realmId` (line 1392) -> `clientMessage` (line 1435) [type=ssrf, conf=0.70]
- `clientArtifactBindingURI` (line 1397) -> `response` (line 1422) [type=xss, conf=0.70]
- `clientArtifactBindingURI` (line 1397) -> `response` (line 1424) [type=xss, conf=0.70]
- `clientArtifactBindingURI` (line 1397) -> `response` (line 1426) [type=xss, conf=0.70]
- `clientArtifactBindingURI` (line 1397) -> `samlDoc` (line 1430) [type=sql_injection, conf=0.70]
- `clientArtifactBindingURI` (line 1397) -> `clientMessage` (line 1432) [type=xxe, conf=0.70]
- `clientArtifactBindingURI` (line 1397) -> `clientMessage` (line 1434) [type=ssrf, conf=0.70]
- `clientArtifactBindingURI` (line 1397) -> `clientMessage` (line 1435) [type=ssrf, conf=0.70]
- `relayState` (line 1399) -> `response` (line 1422) [type=xss, conf=0.70]
- `relayState` (line 1399) -> `response` (line 1424) [type=xss, conf=0.70]
- `relayState` (line 1399) -> `response` (line 1426) [type=xss, conf=0.70]
- `relayState` (line 1399) -> `samlDoc` (line 1430) [type=sql_injection, conf=0.70]
- `relayState` (line 1399) -> `clientMessage` (line 1432) [type=xxe, conf=0.70]
- `relayState` (line 1399) -> `clientMessage` (line 1434) [type=ssrf, conf=0.70]
- `relayState` (line 1399) -> `clientMessage` (line 1435) [type=ssrf, conf=0.70]
- `bindingType` (line 1402) -> `response` (line 1422) [type=xss, conf=0.70]
- `bindingType` (line 1402) -> `response` (line 1424) [type=xss, conf=0.70]
- `bindingType` (line 1402) -> `response` (line 1426) [type=xss, conf=0.70]
- `bindingType` (line 1402) -> `samlDoc` (line 1430) [type=sql_injection, conf=0.70]
- `bindingType` (line 1402) -> `clientMessage` (line 1432) [type=xxe, conf=0.70]
- `bindingType` (line 1402) -> `clientMessage` (line 1434) [type=ssrf, conf=0.70]
- `bindingType` (line 1402) -> `clientMessage` (line 1435) [type=ssrf, conf=0.70]
- `doc` (line 1406) -> `response` (line 1422) [type=xss, conf=0.70]
- `doc` (line 1406) -> `response` (line 1424) [type=xss, conf=0.70]
- `doc` (line 1406) -> `response` (line 1426) [type=xss, conf=0.70]
- `doc` (line 1406) -> `samlDoc` (line 1430) [type=sql_injection, conf=0.70]
- `doc` (line 1406) -> `clientMessage` (line 1432) [type=xxe, conf=0.70]
- `doc` (line 1406) -> `clientMessage` (line 1434) [type=ssrf, conf=0.70]
- `doc` (line 1406) -> `clientMessage` (line 1435) [type=ssrf, conf=0.70]
