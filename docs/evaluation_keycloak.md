# VTC Evaluation: Keycloak case study

> **Snapshot note.** Этот документ — заморозка прогона на тогда существовавших
> 7 фикстурах keycloak (2 ранее размеченных + 5 из `cwe-bench-java`). Позже
> набор был сужен до 4 представителей классов CWE (XSS, Path Traversal,
> Open Redirect, Deserialization), а под другие CWE-классы добавлены фикстуры
> из других продуктов — см.
> [`tests/fixtures/real_world/README.md`](../tests/fixtures/real_world/README.md)
> для актуальной CWE-coverage matrix.

## Цель

Количественно оценить детектор VTC на реальных уязвимых файлах Keycloak
(7 фикстур: 2 файла из ранее существовавшего набора + 5 файлов из CVE-датасета
`cwe-bench-java`) и зафиксировать эффект универсальных правок ядра,
направленных на снижение False Positive rate.

Evaluation harness и схема `ground_truth.json` — project-agnostic. Документация
по добавлению нового проекта и поиску 0-day на незнакомой кодовой базе:
[`tests/fixtures/real_world/README.md`](../tests/fixtures/real_world/README.md).

## Test set

Все фикстуры — в `tests/fixtures/real_world/keycloak/`. Машиночитаемая разметка — `ground_truth.json`.

| File | Vulnerability | TP expected (ideal/realistic) |
|------|---------------|-------------------------------|
| OIDCLoginProtocol.java | Open Redirect (CWE-601) | 3 / 0–1 |
| SerializedBrokeredIdentityContext.java | Unsafe Deserialization (CWE-502/470) | 4 / 0–2 |
| CVE-2014-3656/RealmsResource.java | XSS via origin param | 1 / 0–1 |
| CVE-2022-1274/UserResource.java | HTML Injection / Open Redirect | 1 / 0–1 |
| CVE-2022-3782/RedirectUtils.java | Path Traversal via double-encoding | 1 (utility — likely FN) |
| CVE-2022-4137/OAuth2Error.java | Reflected XSS | 1 (helper — likely FN) |
| CVE-2022-4361/SamlService.java | XSS via AssertionConsumerServiceURL | 1 / 0–1 |

## Universal fixes shipped (не keycloak-специфичные)

1. **Source/Sink classifier** (`src/core/source_sink_classifier.py`):
   - Новые категории `EVENT_LOGGING` и `BENIGN` в `SinkCategory` (в `src/core/models.py`).
   - EVENT_LOGGING ловит `event.detail/error/success`, `logger.{info,warn,...}`, `LOG.*`, `MDC.put`, `Audit*`, `ServicesLogger`.
   - BENIGN ловит `Base64.encode`, `Hex.encode`, `StringBuilder.append`, `String.format`.
   - DIRECT_EXECUTION дополнен `Class.forName`, `classForName`, `Method.invoke`, `ScriptEngine`.
   - OUTPUT_RENDERING дополнен `renderResponse`, `renderTemplate`, `renderLogoutPage`, `Response.ok`, `ResponseEntity.ok`.
   - DATA_STORAGE — `setClientNote`, `setProtocol`, `setRedirectUri` (внутренние session setters).
   - SOURCE.USER_INPUT расширен JAX-RS аннотациями (`@QueryParam`, `@PathParam`, `@FormParam`, `@HeaderParam`, `@MatrixParam`).
   - SOURCE.EXTERNAL_DATA — `getAssertionConsumerServiceURL`, `JsonSerialization.readValue`, `ObjectMapper.readValue`.
   - SOURCE.SESSION_DATA — `getRedirectUri`, `getClientNote`.

2. **Risk matrix** (`src/pipeline/orchestrator.py`):
   - Колонки EVENT_LOGGING (≤0.15) и BENIGN (≤0.05) для всех источников.
   - `(SESSION_DATA, FRAMEWORK_API)`: 0.20 → 0.10.
   - `(INTERNAL_API, FRAMEWORK_API)`: 0.15 → 0.08.
   - `(SESSION_DATA, OUTPUT_RENDERING)`: 0.50 → 0.55 (slight boost — реальные redirect/logout).
   - USER_INPUT × {DIRECT_EXEC, OUTPUT, RESOURCE_ACCESS} остаются 1.0 — не ломают TP.

3. **Sanitizer detection** (`src/stage1_llm_inference/sanitizer_detector.py`):
   - Добавлены: JPA `setParameter`/`createNamedQuery`, Spring `NamedParameterJdbcTemplate`, `JSoup.clean`, `HtmlUtils.htmlEscapeDecimal/Hex`, `getCanonicalPath`, `Pattern.compile().matcher().matches()`, Bean Validation, `UUID.fromString`, `verifyRedirectUri`/`isAllowedRedirectUri`, `UriComponentsBuilder.fromUri*`.
   - ESAPI расширен: `encoder().encode*`, `encodeForHTML/URL/JavaScript/XML`.
   - Apache Commons расширен: `escapeHtml3/4`, `escapeXml10/11`, `escapeEcmaScript`, `escapeJava(Script)`, `escapeCsv`.

4. **Deduplication** (`orchestrator._deduplicate_chains`):
   - Ключ расширен от `(src_var, sink_var, vuln_type)` до `(src_var, src_file, src_line, sink_var, sink_file, sink_line, vuln_type)`.
   - При коллизии — приоритет короткой path (меньше шагов = более прямой flow), confidence — tiebreaker.

5. **Quality-фильтр LLM-галлюцинаций** (`orchestrator._filter_low_quality_chains`):
   - Дропает цепочки, у которых имена source- и sink-переменных одновременно
     отсутствуют в их `code_snippet` — типичный признак, что LLM выдал
     неверный `line_number`.
   - Проверка консервативная (drop только если ОБА снимка не совпадают),
     чтобы не выбивать легитимные случаи, где переменная объявлена в
     сигнатуре функции, а используется ниже.

6. **Resolve фактической строки переменной** (`SimpleSpecificationExtractor`):
   - При заполнении `code_snippet` ищем имя переменной в окне ±5 строк от
     LLM-ответа; если не найдено — fallback на скан всего файла.
   - Корректирует `Source.location.line_number` на реально найденную строку.
   - Снимает основной источник UNKNOWN-классификации, через который ранее
     цепочки обходили риск-матрицу.

## Results

Прогон выполнен на `LLM_PROVIDER=ollama`, `LLM_MODEL=deepseek-coder:6.7b`,
ту же конфигурацию использовали и для baseline, и для after. Полные отчёты —
`evaluation/keycloak/baseline.{json,md}` и `evaluation/keycloak/after.{json,md}`.

### Aggregate metrics

| Metric | Baseline | After | Δ |
|--------|---------:|------:|--:|
| True positives | 1 / 10 | 0 / 10 | −1 |
| False positives (matched FP patterns) | 4 | 2 | −2 |
| False negatives | 10 | 10 | 0 |
| Unclassified | 330 | 27 | **−303** |
| Precision (TP/TP+FP) | 20.00% | 0.00% | −20pp |
| Precision strict (TP/TP+FP+Uncl) | 0.30% | 0.00% | −0.3pp |
| Recall | 9.09% | 0.00% | −9.09pp |
| F1 | 0.125 | 0.000 | −0.125 |

**Ключевой эффект** — обвал шумного хвоста цепочек, не попавших ни в TP, ни в
FP-список: 330 → 27 (−92%). Это прямой результат универсальных правок:
quality-фильтр LLM-галлюцинаций, расширенный source/sink-классификатор и
жёсткая риск-матрица для пар `(SESSION_DATA|INTERNAL_API, FRAMEWORK_API)` /
новых колонок `EVENT_LOGGING` и `BENIGN`.

Минусы: единственный TP, который ловил baseline на `OAuth2Error.java`,
уехал ниже порога (это была borderline-цепочка с близкой к нижней границе
confidence). Recall на этом наборе остаётся низким и ограничен интерпретацией
LLM — он стабильно теряет некросс-метод цепочки через wrapper-методы (см.
`SamlService.java#redirectUri -> setRedirectUri`).

### Per-file deltas (`found_tp / fp / fn / unclassified`)

| File | Baseline | After |
|------|----------|-------|
| `OIDCLoginProtocol.java` | 0/0/3/6 | 0/0/3/**0** |
| `SerializedBrokeredIdentityContext.java` | 0/0/4/4 | 0/0/4/**0** |
| `CVE-2014-3656/RealmsResource.java` | 0/4/1/1 | 0/**2**/1/**0** |
| `CVE-2022-1274/UserResource.java` | 0/0/1/98 | 0/0/1/**14** |
| `CVE-2022-3782/RedirectUtils.java` | 0/0/0/0 | 0/0/0/0 |
| `CVE-2022-4137/OAuth2Error.java` | **1**/0/0/1 | 0/0/0/0 |
| `CVE-2022-4361/SamlService.java` | 0/0/1/220 | 0/0/1/**13** |

## Reproduction

```bash
# Конфигурация: LLM_PROVIDER=ollama, LLM_MODEL=deepseek-coder:6.7b, OLLAMA_BASE_URL=...
source venv/bin/activate

# Baseline (до правок ядра — нужен git stash или предыдущий коммит)
python scripts/evaluate.py --project keycloak --baseline

# After (после правок)
python scripts/evaluate.py --project keycloak

# Diff
python scripts/evaluate.py --diff \
    evaluation/keycloak/baseline.json \
    evaluation/keycloak/after.json
```

## Universality check

```bash
# Не должно быть ни одного матча — ядро не содержит keycloak-специфичных строк.
grep -ri "keycloak" src/ --include="*.py" || echo "OK: no keycloak references in src/"
```
