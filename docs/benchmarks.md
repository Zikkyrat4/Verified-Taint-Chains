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

Default filename полного прогона состоит из backend и LLM mode. Для любого
явного subset добавляется стабильный hash selection, поэтому частичный прогон
не перезапишет полный. `--phase-label` или явные `--save`/`--report-md` задают
имя вручную.

По умолчанию область ограничена CWE, которые VTC явно заявляет как
поддерживаемые. Это фиксированный capability set из кода, а не список примеров,
которые текущая версия успешно находит. `--all-cwes` включает все upstream CWE
и обязательно записывается в отчет.

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
precision, recall, specificity и F1.

Testcases анализируются project-mode пакетами, чтобы Stage 1 использовал
параллелизм OpenAI/Ollama. Граф VTC остается scoped по файлам, поэтому один
testcase не может создать цепь в другом. Incomplete extraction и ошибки batch-а
исключаются из матрицы ошибок и отдельно уменьшают execution coverage.

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
