# Оценка VTC

Ground truth из `tests/fixtures/real_world/*/ground_truth.json` читает только
evaluator после завершения анализа. Пайплайн, LLM и статический baseline эти
файлы не получают. Режим анализа и модель записываются в каждый JSON/Markdown
отчёт; результаты `llm`, `static` и `hybrid` не объединяются.

## Методика

Основная оценка строгая:

- все записи `true_positives` участвуют в recall, включая помеченные в старых
  фикстурах как `expected_realistic=false`;
- source и sink совпадают по точному каноническому Java-идентификатору;
- тип уязвимости должен совпасть точно;
- объявленные файлы должны совпасть по точному относительному суффиксу пути;
- допустимое отклонение source/sink line равно `±5`;
- один finding может соответствовать не более чем одному TP;
- промежуточный узел пути, alias или CWE модели не заменяют неверный endpoint
  или тип.

`Known FP` означает совпадение с размеченным false-positive pattern. `Other`
сохраняется отдельным списком для ручного триажа, но в основной precision
считается ложным срабатыванием:

```text
precision = TP / (TP + Known FP + Other)
recall    = TP / (TP + FN)
```

`P known = TP / (TP + Known FP)` публикуется только как диагностическая
величина для уже размеченных findings. Она не является основной precision.

## Результаты

Отчёты `evaluation/*/{static,llm,hybrid}-honest.{json,md}` пересчитаны на
неизменённом ground truth из 18 положительных цепочек:

| Backend | TP | Known FP | FN | Other | Precision | P known | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `static` | 4 | 1 | 14 | 6 | 36.36% | 80.00% | 22.22% | 0.2759 |
| `llm` | 6 | 5 | 12 | 46 | 10.53% | 54.55% | 33.33% | 0.1600 |
| `hybrid` | 6 | 7 | 12 | 44 | 10.53% | 46.15% | 33.33% | 0.1600 |

LLM-прогон использовал `analysis_backend=llm`, provider `openai`, модель
`glm-5.3-flash` и `llm_analysis_mode=targeted`. На этом небольшом наборе LLM
находит больше размеченных цепочек, чем static, но генерирует много
неразмеченных findings. Hybrid не улучшает recall и добавляет известные FP.
Эти результаты не подтверждают высокую точность системы.

В основном LLM-режиме модель выбирает sources, sinks и sanitizers. AST затем
нормализует расположение и scope, строит data-flow и проверяет структурную
достижимость, но не создаёт отсутствующие source/sink. `static` является
отдельным детерминированным baseline. `hybrid` явно объединяет обе выборки.

## Производительность

На использованном OpenAI-compatible endpoint полный холодный прогон занял
`237.59 s` для LLM и `249.10 s` для hybrid. Это реальная сетевая latency, а не
скорость анализа из кэша. Повторный прогон тех же спецификаций занял `7.32 s`
и `7.66 s` соответственно; static занял `7.05 s`.

Клиент переиспользует асинхронный HTTP transport, отключает скрытые retries
OpenAI SDK, объединяет методы в batch, ограничивает параллелизм и кэширует
Stage 1 по содержимому, provider, model, backend, режиму и версии prompt.
`--refresh-specs` намеренно обходит чтение кэша и снова оплачивает latency
endpoint. Увеличение `MAX_CONCURRENT_FUNCTIONS` может ускорить cold run, но
повышает риск rate limit.

## Воспроизведение

```bash
# Свежий LLM-прогон без чтения старых ответов
vtc evaluate --all-projects \
  --backend llm --phase-label llm-honest --refresh-specs

# Повторная оценка тех же ответов из content-addressed cache
vtc evaluate --all-projects \
  --backend llm --phase-label llm-honest

# Независимые baseline/ablation
vtc evaluate --all-projects \
  --backend static --phase-label static-honest
vtc evaluate --all-projects \
  --backend hybrid --phase-label hybrid-honest --refresh-specs
```

LLM-ответы могут различаться между свежими прогонами даже при temperature 0,
поэтому сравнивать изменения следует на нескольких cold runs или на одном
зафиксированном наборе кэшированных ответов. Схема ground truth описана в
[`tests/fixtures/real_world/README.md`](../tests/fixtures/real_world/README.md).
