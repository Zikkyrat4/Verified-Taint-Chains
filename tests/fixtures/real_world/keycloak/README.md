# Keycloak — Ground Truth Notes

Версия: 24.0.0 (pre-fix). Машиночитаемая разметка — `ground_truth.json`.
Документ описывает каждую цепочку: ожидаемый source/sink, известные FP-паттерны, лимиты текущего детектора.

---

## 1. OIDCLoginProtocol.java (CVE-2024-2419 — Open Redirect, CWE-601)

**CVE:** https://nvd.nist.gov/vuln/detail/CVE-2024-2419
**Severity:** HIGH (CVSS 7.1)
**Description:** redirect_uri из OIDC authorization request сохраняется в auth session и используется для редиректа без достаточной валидации. Атакующий может подставить произвольный URL.

### True Positives

#### TP-1: Open Redirect в `authenticated()` (lines 215-303)
- **Source:** `authSession.getRedirectUri()` (line 215) — redirect_uri из auth session, изначально от пользователя
- **Sink:** `redirectUri.build()` (line 303) — формирует HTTP redirect response
- **Flow:** `redirect` (line 215) -> `OIDCRedirectUriBuilder.fromUri(redirect, ...)` (line 216) -> `redirectUri.build()` (line 303)
- **Expected categories:** source=SESSION_DATA, sink=OUTPUT_RENDERING or FRAMEWORK_API

#### TP-2: Open Redirect в `sendError()` (lines 321-345)
- **Source:** `authSession.getRedirectUri()` (line 321)
- **Sink:** `redirectUri.build()` (line 345)
- **Flow:** `redirect` -> `OIDCRedirectUriBuilder.fromUri(redirect, ...)` -> `redirectUri.build()`
- **Expected categories:** source=SESSION_DATA, sink=OUTPUT_RENDERING or FRAMEWORK_API

#### TP-3: Open Redirect в `finishBrowserLogout()` (lines 392-400)
- **Source:** `logoutSession.getAuthNote(OIDCLoginProtocol.LOGOUT_REDIRECT_URI)` (line 392)
- **Sink:** `frontChannelLogoutHandler.renderLogoutPage(finalRedirectUri)` (line 400)
- **Flow:** `redirectUri` -> `LogoutUtil.getRedirectUriWithAttachedState(redirectUri, ...)` -> `renderLogoutPage(finalRedirectUri)`
- **Expected categories:** source=SESSION_DATA, sink=OUTPUT_RENDERING or FRAMEWORK_API

### Known Difficulties
- `getRedirectUri()` not classified as SESSION_DATA by default — falls into INTERNAL_API.
- `redirectUri.build()` matches as FRAMEWORK_API via `new \w+\(` pattern.
- Pair (SESSION_DATA, FRAMEWORK_API) gets multiplier ≤0.10 — may be filtered. Realistic: 0–1 TP found.

---

## 2. SerializedBrokeredIdentityContext.java (Unsafe Deserialization, CWE-502/470)

**Context:** Файл содержит паттерны unsafe deserialization, характерные для цепочек атак через identity provider federation.
**Severity:** HIGH

### True Positives

#### TP-1: Unsafe Reflection в `deserialize()` (line 292)
- **Source:** `value.getClazz()` — имя класса из сериализованного контекста
- **Sink:** `Reflections.classForName(value.getClazz(), ...)`
- **Flow:** Attacker-controlled class name -> reflection class loading -> arbitrary class instantiation
- **Expected categories:** source=INTERNAL_API, sink=DIRECT_EXECUTION

#### TP-2: Unsafe Deserialization в `deserialize()` (line 294)
- **Source:** `value.getData()`
- **Sink:** `serializer.deserialize(value.getData(), clazz)`
- **Expected categories:** source=INTERNAL_API, sink=DIRECT_EXECUTION

#### TP-3: JSON Deserialization в `readFromAuthenticationSession()` (lines 344-349)
- **Source:** `authSession.getAuthNote(noteKey)` (line 344)
- **Sink:** `JsonSerialization.readValue(asString, SerializedBrokeredIdentityContext.class)` (line 349)
- **Expected categories:** source=SESSION_DATA, sink=DIRECT_EXECUTION

#### TP-4: JSON Deserialization в `getAttributeStream()` (lines 244-246)
- **Source:** `ctxEntry.getData()` (line 244)
- **Sink:** `JsonSerialization.readValue(asBytes, List.class)` (line 246)
- **Expected categories:** source=INTERNAL_API, sink=DIRECT_EXECUTION

### Known Difficulties
- `Reflections.classForName(...)` — расширенный classifier теперь матчит, попадает в DIRECT_EXECUTION.
- `JsonSerialization.readValue(...)` сложно поймать как sink (нет прямого паттерна), часто остаётся UNKNOWN/FRAMEWORK_API.
- Реальная цепочка идёт через `authSession -> JSON parse -> Reflections.classForName` — getter-вид не очевиден для LLM.

---

## 3. CVE-2022-3782 / RedirectUtils.java (Path Traversal, CWE-22)

**CVE:** CVE-2022-3782 — path traversal via double URL encoding.
**Severity:** HIGH (CVSS 8.1)

### True Positive

#### TP-1: insufficient redirectUri validation
- **Source:** `redirectUri` (line 90) — параметр функции; в реальном вызове приходит из HTTP query
- **Sink:** возвращаемое значение функции, через `URI.create(redirectUri)` (line 96) и `redirectUri.normalize().toString()` (line 97)
- **Flow:** `redirectUri` (line 90) -> `URI.create()` (line 96) -> `lowerCaseHostname(redirectUri)` (line 119) -> `redirectUri = relativeToAbsoluteURI(...)` (line 144)
- **Expected categories:** source=USER_INPUT (parameter from HTTP), sink=OUTPUT_RENDERING/RESOURCE_ACCESS

### Known Difficulties
- Это утилитный класс — реальный source приходит снаружи. Инструмент может не пометить параметр как USER_INPUT.
- Цепочка короткая, нет явного опасного sink-паттерна — высока вероятность FN.

---

## 4. CVE-2022-4361 / SamlService.java (XSS, CWE-79)

**CVE:** CVE-2022-4361 — XSS via AssertionConsumerServiceURL.
**Severity:** MEDIUM (CVSS 6.1)

### True Positive

#### TP-1: AssertionConsumerServiceURL not sanitized for HTML
- **Source:** `requestAbstractType.getAssertionConsumerServiceURL()` (line 424) — поле из десериализованного SAML XML
- **Sink:** `authSession.setRedirectUri(redirect)` (line 461) — сохраняется в session, позже используется в template
- **Flow:** `redirectUri` (line 424) -> `redirect = RedirectUtils.verifyRedirectUri(...)` (line 426) -> `authSession.setRedirectUri(redirect)` (line 461)
- **Expected categories:** source=EXTERNAL_DATA (deserialized XML), sink=DATA_STORAGE

---

## Summary: Expected Metrics (4 файла)

| Metric | Value |
|--------|-------|
| True Positives (ideal) | 9 |
| True Positives (realistic) | 1–4 |
| False Positives (baseline) | 25–45 |
| False Positives (after filter) | 5–15 |
| FP Reduction | ~55–65% |

**Note:** для framework-кода основная ценность category filter — не обнаружение новых TP, а подавление FP. Настоящие уязвимости (redirect, deserialization) используют нестандартные sink-паттерны, которые сложно детектировать regex-классификатором.
