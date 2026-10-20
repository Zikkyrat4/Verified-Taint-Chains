# Зафиксированные результаты тестирования

Этот документ фиксирует проверенный снимок результатов VTC на 20 октября
2026 года. Полные отчеты остаются локальными в `evaluation/benchmarks/` и не
попадают в Git из-за размера. Здесь сохранены параметры запусков, итоговые
метрики и SHA-256 исходных JSON/Markdown, чтобы результат можно было проверить
и не перепутать с ранними экспериментами.

## Сводка

| Проверка | Дата запуска, UTC | Область | Режим | Итог | Ошибки |
|---|---|---|---|---|---:|
| Unit/integration tests | 2026-10-20 | 1108 тестов | `pytest -q` | 1108 passed, 176 warnings | 0 |
| OWASP BenchmarkJava 1.2 | 2026-10-20 13:17 | 1478 поддерживаемых testcase | cold LLM, `exhaustive` | F1 0.6320, OWASP score 8.34% | 0 |
| CWE-Bench-Java | 2026-10-19 14:14 | 151 CVE, из них 138 scored | LLM cache replay, `exhaustive` | verified recall 43.48% | 0 |

OWASP и CWE-Bench используют разные единицы и oracle, поэтому их метрики нельзя
агрегировать или напрямую сравнивать. OWASP размечает безопасные и уязвимые
testcase и позволяет считать precision. CWE-Bench размечает scope конкретного
CVE, но не все остальные уязвимости реального проекта, поэтому precision для
него не определена.

## Общая конфигурация

Оба финальных отчета относятся к одной реализации:

| Параметр | Значение |
|---|---|
| Implementation digest | `26d7f0037f79e0bfdbe64dd98a7ed5191b33d400759fe6688b72568668c1305b` |
| Backend | `llm` |
| LLM mode | `exhaustive` |
| Provider / model | OpenAI-compatible / `glm-5.3-flash` |
| Temperature | `0.0` |
| Provider seed | недоступен |
| Prompt / extractor version | `14` / `29` |
| Fast prefilter | выключен |
| Candidate top-k | выключен (`max_candidate_chains=0`) |
| Endpoint graph file limit | выключен (`max_endpoint_graph_files=0`) |
| Graph | `enhanced_ast`, LLM enrichment выключен |
| Verification | CFG + symbolic, в scoring только `verified` |
| Joern | выключен |
| Python hash seed | `0` |

В этом режиме только LLM создает source, sink и sanitizer. AST-граф, поиск
путей и verification являются детерминированными частями end-to-end
LLM-backed анализатора. Статические endpoints в `backend=llm` не подмешиваются.

## OWASP BenchmarkJava

### Протокол

| Поле | Значение |
|---|---|
| Upstream revision | `51f0a7cf8bb9d17ce1f6d72598c1d1c6ce90f661` |
| Upstream cases | 2740 |
| Выбранная область | 1478 cases: CWE-22, CWE-78, CWE-79, CWE-89 |
| Единица scoring | один binary prediction на официальный testcase |
| Stage 1 cache reads | нет (`--refresh-specs`) |
| Параллелизм | 16 files, не более 5 LLM requests |
| Длительность | 1422.718 s |

Команда:

```bash
PYTHONHASHSEED=0 vtc benchmark run owasp-java \
  --backend llm \
  --llm-analysis-mode exhaustive \
  --refresh-specs \
  --fail-fast \
  --max-concurrent-files 16 \
  --max-concurrent-llm-requests 5 \
  --save evaluation/benchmarks/owasp-java/glm-5.3-flash-exhaustive-isolated-current-cold-20261020.json \
  --report-md evaluation/benchmarks/owasp-java/glm-5.3-flash-exhaustive-isolated-current-cold-20261020.md
```

Идентификаторы cases, comments и искусственные benchmark category markers были
скрыты от LLM. Testcase не разделяли LLM context, а cross-testcase graph bridges
были запрещены.

### Результат

| TP | FP | TN | FN | Precision | Recall | Specificity | F1 | OWASP score |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 577 | 472 | 229 | 200 | 55.00% | 74.26% | 32.67% | 0.6320 | 8.34% |

| CWE | TP | FP | TN | FN | Recall | FPR | OWASP score | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| CWE-22 | 109 | 89 | 46 | 24 | 81.95% | 65.93% | 16.03% | 0.6586 |
| CWE-78 | 97 | 83 | 42 | 29 | 76.98% | 66.40% | 10.58% | 0.6340 |
| CWE-79 | 138 | 120 | 89 | 108 | 56.10% | 57.42% | -1.32% | 0.5476 |
| CWE-89 | 233 | 180 | 52 | 39 | 85.66% | 77.59% | 8.08% | 0.6803 |

Stage 2 до verifier: TP 599, FP 521, TN 180, FN 178, precision 53.48%,
recall 77.09%, F1 0.6315.

Независимая проверка повторно загрузила официальный CSV, подтвердила порядок и
метаданные всех 1478 cases, заново рассчитала обе confusion matrix и проверила
2,867 verified/candidate findings, 14,779 координат в 1,163 файлах. Расхождений,
orphan findings и cross-case цепочек нет. Markdown точно воспроизводится из
JSON.

Локальные артефакты:

| Файл | Размер | SHA-256 |
|---|---:|---|
| `glm-5.3-flash-exhaustive-isolated-current-cold-20261020.json` | 7,349,525 B | `227e1f449443cd63386ab8a6af53fc7c11f59fdd2fb48592f1a6bd2ff6d5ac7d` |
| `glm-5.3-flash-exhaustive-isolated-current-cold-20261020.md` | 32,440 B | `3b27c69130e077f73a8e879783e4405fc627e504f16e762572f40048f43e58ee` |

## CWE-Bench-Java

### Протокол

| Поле | Значение |
|---|---|
| Upstream revision | `3a12f45750f58135bcc58c7fdf4c20786b600e31` |
| Выбранная область | 151 CVE из заявленных VTC CWE |
| Единица scoring | target CVE в официальном fix scope |
| Stage 1 | cache-only replay сохраненных LLM-ответов |
| Параллелизм replay | 16 files, лимит LLM requests 3 |
| Длительность, сохраненная в отчете | 27653.386 s |

Команда:

```bash
PYTHONHASHSEED=0 vtc benchmark run cwe-bench-java \
  --backend llm \
  --llm-analysis-mode exhaustive \
  --cache-only \
  --fail-fast \
  --max-concurrent-files 16 \
  --max-concurrent-llm-requests 3 \
  --phase-label glm-5.3-flash-exhaustive-cache-replay-final-20261019
```

Cache replay не выполнял новые LLM-запросы: он повторно применил сохраненные
ответы Stage 1 к исправленным Stage 2/3 и scorer. 98 уже завершенных cases были
восстановлены из checkpoint только после проверки `analysis_complete`,
отсутствия ошибок и семантически идентичного replay case 4. Unlimited graph
retention впервые влиял на еще не сохраненный case 101.

### Результат

| Selected | Scored | TP | FN | Verified recall | Candidate hits | Candidate recall | Errors |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 151 | 138 | 60 | 78 | 43.48% | 66 | 47.83% | 0 |

| CWE | TP | FN | Recall |
|---|---:|---:|---:|
| CWE-22 | 39 | 17 | 69.64% |
| CWE-502 | 1 | 6 | 14.29% |
| CWE-611 | 3 | 3 | 50.00% |
| CWE-78 | 4 | 9 | 30.77% |
| CWE-79 | 9 | 25 | 26.47% |
| CWE-89 | 0 | 2 | 0.00% |
| CWE-918 | 0 | 2 | 0.00% |
| CWE-94 | 4 | 14 | 22.22% |

13 selected cases не вошли в знаменатель recall:

| Причина | Cases |
|---|---:|
| Нет localization oracle | 2 |
| Oracle вне поддерживаемого scope | 3 |
| Vulnerable source недоступен | 6 |
| Нет vulnerable revision | 2 |

Независимая проверка заново построила official vulnerable-source AST scope и
подтвердила все 138 TP/FN. Проверены 259,286 findings, 3,379 oracle-scope
candidates и 1,311,171 сериализованный узел в 50,241 файле. Невалидных путей или
номеров строк нет; execution errors и incomplete analysis отсутствуют.

Локальные артефакты:

| Файл | Размер | SHA-256 |
|---|---:|---|
| `glm-5.3-flash-exhaustive-cache-replay-final-20261019.json` | 630,758,791 B | `6b4b9be51490ed07f4da903b27a1bbd31722fe16d214abc0d3ec9b48f7d83a6a` |
| `glm-5.3-flash-exhaustive-cache-replay-final-20261019.md` | 4,917 B | `ab20f0af75aeec831e9fe5bcc620d61831a61ad5383bf3de30d70ce5703aabd3` |

## Ограничения

- Публичные benchmark могли присутствовать в pretraining модели. Prompt
  redaction убирает прямые подсказки, но не устраняет этот риск полностью.
- OpenAI-compatible provider не поддерживает управляемый seed. Cold runs могут
  различаться даже при `temperature=0`; один прогон не является оценкой
  статистического разброса.
- CWE-Bench precision намеренно не рассчитывается: unmatched finding в большом
  реальном проекте нельзя честно объявить FP без полной разметки проекта.
- Полные JSON содержат диагностические findings и слишком велики для обычного
  GitHub. CWE JSON также превышает лимит GitHub 100 MiB. Проверять локальный
  артефакт следует по SHA-256 из этого документа.

При новом финальном прогоне этот файл обновляется только после проверки
oracle, integrity flags, implementation digest, отсутствия execution errors и
повторного запуска `pytest -q`. Исторический снимок нельзя молча перезаписывать
результатами другой модели, backend или режима анализа.
