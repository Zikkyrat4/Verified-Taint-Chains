# External benchmarks

`vtc benchmark` запускает публичные наборы через тот же `SimplePipeline`, что и
обычный анализ. Локальная команда `vtc evaluate` остается быстрым regression
suite проекта; ее результаты нельзя агрегировать с внешними benchmark-ами.

## Зафиксированные наборы

| ID | Upstream | Pin | Единица оценки |
|---|---|---|---|
| `owasp-java` | OWASP BenchmarkJava 1.2 | `51f0a7cf8bb9d17ce1f6d72598c1d1c6ce90f661` | testcase |
| `cwe-bench-java` | IRIS / CWE-Bench-Java | `3a12f45750f58135bcc58c7fdf4c20786b600e31` | CVE |

Pin — полный Git commit SHA. `fetch` делает detached checkout и проверяет SHA и
обязательные oracle-файлы. Upstream-код не vendored в VTC: он сохраняется в
`.vtc-benchmarks/` (или в `VTC_BENCHMARK_DIR`) и не попадает в Git. Это также
сохраняет границы лицензий: BenchmarkJava распространяется под GPL-2.0, IRIS —
под MIT.

Структура локального хранилища:

```text
.vtc-benchmarks/
├── upstream/                   # pinned benchmark repositories and oracle
├── cases/cwe-bench-java/0001/  # exact vulnerable project revisions
└── cache/                      # Stage 1 cache, separate for each suite
```

CWE-проекты лежат в числовых каталогах. CVE и project slug не попадают в путь,
который передается Stage 1. Oracle читается scorer-ом только после анализа;
ожидаемый CWE также не передается pipeline.

## Workflow

```bash
vtc benchmark list
vtc benchmark validate

vtc benchmark fetch owasp-java
vtc benchmark run owasp-java --backend llm

vtc benchmark fetch cwe-bench-java
vtc benchmark prepare cwe-bench-java --cwe CWE-22 --limit 10 --seed 42
vtc benchmark run cwe-bench-java --cwe CWE-22 --limit 10 --seed 42 --backend llm
```

Для `prepare` и `run` CWE-Bench следует передавать одинаковые `--cwe`,
`--case`, `--limit`, `--seed`, `--all-cwes` и `--include-tests`. Sampling применяется только при
явном `--limit` и детерминирован `--seed`. Без лимита выполняется весь выбранный
набор. `--refresh-specs` запрещает чтение Stage 1 cache; запись кэша остается
включенной для последующего воспроизводимого повтора.
`--retry-errors` повторно запускает только CWE-Bench cases со статусом `error`
в совместимом checkpoint; сохраненные `tp`, `fn` и unscored-строки не меняются.
Глобальная нагрузка на LLM ограничивается через
`--max-concurrent-llm-requests` независимо от числа одновременно
обрабатываемых файлов и function batches.

External benchmark принудительно устанавливает `max_files=0` и
`fast_prefilter=false`: ни локальный профиль, ни ENV не могут молча исключить
часть выбранных файлов. Режим отбора методов всё равно задаётся явно через
`--llm-analysis-mode` и записывается в отчёт.

Default filename полного прогона состоит из backend и LLM mode. Для любого
явного subset добавляется стабильный hash selection, поэтому частичный прогон
не перезапишет полный. `--phase-label` или явные `--save`/`--report-md` задают
имя вручную.

По умолчанию область ограничена CWE, которые VTC явно заявляет как
поддерживаемые. Это фиксированный capability set из кода, а не список примеров,
которые текущая версия успешно находит. `--all-cwes` включает все upstream CWE
и обязательно записывается в отчет.

## Протокол проверки LLM-режима

`backend=llm` означает, что source/sink создаёт только LLM. Построение графа и
verification остаются детерминированными этапами VTC, поэтому итоговые метрики
измеряют LLM-режим всего анализатора, а не изолированную модель-классификатор.
LLM получает ограниченный call-context реально вызываемых project-local методов
(до двух уровней), как и при обычном `vtc analyze-project`. Комментарии из
целевого кода и подключаемых helper-методов удаляются только из LLM-промпта с
сохранением номеров строк. Это исключает подсказки `safe`/`vulnerable` из
публичного корпуса, не меняя код для AST и verification. Детерминированная
валидация схемы и привязка endpoint к реальной строке не создают source/sink и
явно записываются в `run.context.deterministic_validation`. Отбрасывание source
по статически доказанному constant-return project call применяется только в
`backend=hybrid`; в чистом `backend=llm` оно отключено.

OWASP JSON явно описывает измерение в `run.measurement`. Primary metric
`verified_chain_same_cwe` оценивает полный LLM-backed analyzer. Диагностика
`stage2_candidate_aggregate` показывает результат LLM-derived endpoints и графа
до verifier. Это всё ещё не raw binary verdict модели: LLM в архитектуре VTC
возвращает endpoints, а не ответ vulnerable/safe, и OWASP не предоставляет
endpoint-level oracle для прямого precision/recall Stage 1.

Сначала выполняется холодный smoke на фиксированной выборке:

```bash
vtc config validate
vtc benchmark validate

vtc benchmark run owasp-java \
  --backend llm --llm-analysis-mode exhaustive \
  --limit 50 --seed 20260925 --refresh-specs \
  --max-concurrent-llm-requests 5 \
  --phase-label glm-5.3-flash-exhaustive-smoke-cold
```

После smoke запускаются полные поддерживаемые наборы без `--limit`:

```bash
vtc benchmark run owasp-java \
  --backend llm --llm-analysis-mode exhaustive --refresh-specs \
  --max-concurrent-llm-requests 5 \
  --phase-label glm-5.3-flash-exhaustive-cold

vtc benchmark prepare cwe-bench-java
vtc benchmark run cwe-bench-java \
  --backend llm --llm-analysis-mode exhaustive --refresh-specs \
  --max-concurrent-llm-requests 5 \
  --phase-label glm-5.3-flash-exhaustive-cold
```

`exhaustive` показывает максимальный охват LLM: анализируются все обнаруженные
методы, включая тривиальные и source-only boundaries. Отдельный прогон с
`--llm-analysis-mode targeted` измеряет быстрый
production-режим с предварительным отбором методов; его результаты нельзя
объединять с `exhaustive`.

Перед публикацией в JSON проверяются следующие поля:

```bash
jq '{analysis: (.run.analysis | {
  backend, llm_analysis_mode, llm_provider, llm_model,
  fast_prefilter, cache_read_enabled, use_joern,
  verification_enabled, verification_result_policy
}), integrity: .run.integrity, aggregate: .aggregate}' \
  evaluation/benchmarks/owasp-java/glm-5.3-flash-exhaustive-cold.json
```

Для холодного честного прогона ожидаются `backend="llm"`,
`llm_analysis_mode="exhaustive"`, `fast_prefilter=false`,
`cache_read_enabled=false`, `verification_enabled=true`,
`verification_result_policy="verified_only"` и
`oracle_exposed_to_pipeline=false`. Execution errors не считаются FN: их надо
публиковать отдельно и по возможности повторять (`--retry-errors` для
CWE-Bench). Один smoke следует повторить несколько раз с новой `phase-label`,
чтобы оценить разброс недетерминированной модели.

## Scoring

Benchmark finding — только цепочка со статусом `verification_status=verified`.
`unverifiable` не является положительным предсказанием и хранится только в
диагностике pipeline. Адаптер дополнительно проверяет этот контракт и завершает
case с ошибкой, если в `verified_chains` оказался иной статус. Запуск внешних
наборов с `VERIFICATION_ENABLED=false` запрещен.

CWE-Bench дополнительно публикует `candidate_scope_recall`: долю CVE, для
которых Stage 2 нашла цепочку нужного CWE в официальном scope до строгой
символьной проверки. Это диагностическая метрика; кандидаты не становятся TP.

### OWASP BenchmarkJava

Oracle `expectedresults-1.2.csv` содержит положительную или отрицательную метку
и CWE для каждого testcase. VTC формирует одну бинарную prediction на testcase:
наличие хотя бы одной verified chain того же CWE. Несколько одинаковых цепочек
не увеличивают TP или FP. Поэтому корректно рассчитываются TP, FP, TN, FN,
precision, recall, specificity и F1. Дополнительно публикуется официальный
OWASP score: для каждого CWE `TPR - FPR`, общий score — невзвешенное среднее
по CWE. Micro score остаётся диагностическим и не подменяет официальный.

Идентификатор `BenchmarkTestNNNNN` заменяется только в LLM prompt на нейтральный
`EvaluationCase`; исходный файл для AST/графа не меняется. Это не устраняет риск
запоминания публичного корпуса моделью, но не даёт ей прямой ключ к testcase.
Комментарии testcase также не передаются модели, поскольку официальный корпус
содержит текстовые подсказки о безопасных и небезопасных ветках.
Искусственные маркеры категории из test harness (`/pathtraver-*`, `/cmdi-*`,
`/sqli-*`, `/xss-*`, диагностические строки `cmdi` и заголовок
`X-XSS-Protection`) в LLM prompt также заменяются нейтральными значениями. Это
не меняет исходники или граф и не позволяет узнать ожидаемый CWE из имени
маршрута вместо анализа потока данных.
Все Java helper-файлы, не являющиеся официальными testcases, доступны как
context-only: они нужны для корректного межфайлового анализа, но не извлекаются
как отдельные findings и не оцениваются.

Testcases анализируются project-mode пакетами, чтобы Stage 1 использовал
параллелизм OpenAI/Ollama. Пакет является только механизмом конкурентного
исполнения: testcase не включаются в LLM context друг друга, а межфайловые graph
bridges между ними отключены. Адаптер дополнительно проверяет source, sink и все
path nodes каждой цепочки и аварийно завершает запуск при пересечении двух
testcase. Incomplete extraction и ошибки batch-а исключаются из матрицы ошибок
и отдельно уменьшают execution coverage.

Project-mode использует ограниченные по размеру пакеты Stage 1 и Stage 2. Для
проектов крупнее 20 000 Java-файлов LLM по-прежнему анализирует каждый выбранный
файл. После Stage 1 строится компактный глобальный индекс определений и вызовов,
а NetworkX-граф получает endpoint-файлы и connector-файлы на поддерживаемых
направленных путях source-to-sink. Межфайловые bridges разрешаются только для
глобально уникального владельца метода. Если индекс или retained slice не
помещается в safety limit, сохраненные находки не теряются, но отрицательный
результат остается execution error, а не FN.

Усеченный Stage 1 ответ рекурсивно дробится до отдельных методов. Крупный
одиночный метод дополнительно делится на перекрывающиеся source-фрагменты с
сохранением абсолютных line offsets; небольшой неделимый ответ получает budget
до `LLM_TRUNCATION_MAX_TOKENS`. `MAX_CANDIDATE_CHAINS` применяется как
детерминированный глобальный top-k по confidence source/sink, а не как первые
K пар в порядке обхода. Metrics получает `candidate_selection_limited=true`,
`candidate_pairs_ranked` и `candidate_pairs_ranked_out`. Это ограниченная
политика выбора, а не execution error; неполными по-прежнему считаются только
ошибки extraction, graph slice и endpoint retention.

### CWE-Bench-Java

Все cases являются известными CVE, но upstream не размечает каждую возможную
уязвимость в полном real-world проекте. Поэтому primary metric — CVE recall:
verified chain ожидаемого CWE должна пересечь официальный fix method/scope.
Matcher сначала сравнивает file + method name, так как upstream line ranges
относятся к fixed revision. Если chain location не содержит method name,
используется явно отмеченный fallback по fixed line range с допуском 10 строк.
Для curated subset дополнительно считается точное попадание в ручную пару
source/sink с допуском 5 строк.

Finding ожидаемого CWE вне fix scope и findings других CWE сохраняются в JSON
как unscored. Считать их FP нельзя: отсутствие записи в частичном oracle не
доказывает безопасность. По этой причине CWE-Bench отчет намеренно возвращает
`precision: null` с объяснением, а не публикует вводящее в заблуждение число.
`oracle_scope_candidates` отдельно сохраняет кандидатов Stage 2, попавших в
эталонный scope, вместе со статусом, методом и причиной Stage 3. Это позволяет
отличить ошибку extraction/path discovery от отклонения verifier без включения
oracle в сам анализ.

Строки dataset без `buggy_commit_id`, без доступного checkout или без
localization oracle не превращаются в FN. Scorer также проверяет oracle path по
Java-файлам уязвимой ревизии: переименованный, отсутствующий или Groovy-only
target получает `unscored_oracle_source_unavailable`. При выключенном
`--include-tests` test-only oracle получает `unscored_oracle_out_of_scope`.

## Честность сравнения

JSON фиксирует upstream SHA, backend (`llm`, `static`, `hybrid`), модель,
провайдера, analysis mode, параметры pipeline, selection, seed, runtime и ошибки.
Результаты разных backend/model/subset нельзя агрегировать в одну метрику.

Оба набора публичны, поэтому нельзя исключить, что pretrained LLM видел их код.
Отчет явно записывает этот contamination risk. Oracle и CVE metadata при этом не
добавляются в prompt. Для научного сравнения следует публиковать полный JSON,
точный model identifier, environment config и execution coverage, а не только
итоговый F1/recall.

Checkpoint имеет версионированную схему. Изменение контракта verified-only
инвалидирует старый checkpoint автоматически, поэтому результаты до и после
изменения нельзя смешать или продолжить одним файлом.
