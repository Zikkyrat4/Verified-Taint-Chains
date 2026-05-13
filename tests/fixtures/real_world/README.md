# Real-world fixtures

Каждая поддиректория здесь — отдельный **проект** для прогона эталонной
оценки VTC. Структура одного проекта:

```
real_world/<project>/
  ground_truth.json          # машиночитаемая разметка TP / known-FP
  README.md                  # (опц.) человекочитаемое описание
  <File>.java                # фикстуры — реальные уязвимые файлы
  <CVE-XXXX-YYYY>/<File>.java
  ...
```

Добавление нового проекта не требует правок ядра — только новой директории
и валидного `ground_truth.json`. Структурный регрессионный тест:
`pytest tests/unit/test_real_world_fixtures.py`.

## CWE-coverage matrix

10 .java файлов в 6 проектах, 6 классов уязвимостей. Источник CVE —
[`cwe-bench-java`](https://github.com/iris-sast/cwe-bench-java) +
ранее размеченные Keycloak-кейсы.

| CWE | Класс | Project | File |
|-----|-------|---------|------|
| CWE-022 | Path Traversal | keycloak | `CVE-2022-3782/RedirectUtils.java` |
| CWE-022 | Path Traversal | spark | `CVE-2018-9159/ClassPathResource.java` |
| CWE-078 | OS Command Injection | jenkins-docker-commons | `CVE-2022-20617/DockerRegistryEndpoint.java` |
| CWE-078 | OS Command Injection | jenkins-perfecto | `CVE-2020-2261/PerfectoBuildWrapper.java` |
| CWE-079 | XSS | keycloak | `CVE-2022-4361/SamlService.java` |
| CWE-079 | XSS | jspwiki | `CVE-2019-10076/LinkToTag.java` |
| CWE-094 | Code Injection | cron-utils | `CVE-2021-41269/CronParser.java` |
| CWE-094 | Code Injection | spring-framework | `CVE-2022-22965/CachedIntrospectionResults.java` (Spring4Shell) |
| CWE-502 | Unsafe Deserialization | keycloak | `SerializedBrokeredIdentityContext.java` |
| CWE-601 | Open Redirect | keycloak | `OIDCLoginProtocol.java` |

## ground_truth.json — схема

```jsonc
{
  "files": {
    "<rel/path/inside/project>.java": {
      "cve": "CVE-2024-XXXXX",          // optional, для отчёта
      "cwe": "CWE-022",                  // optional, для отчёта
      "vulnerability": "Path Traversal", // optional, описание

      "true_positives": [
        {
          "id": "TP-1",                  // unique within file
          "source_var": "redirect",      // имя source-переменной
          "sink_var": "redirectUri",
          "source_line": 215,            // 1-indexed; 0 = unknown
          "sink_line": 303,
          "vuln_type": "xss",            // xss | sql_injection | command_injection | path_traversal | xxe | ssrf | deserialization | open_redirect | code_injection
          "description": "что именно за поток и почему это уязвимость",
          "expected_realistic": true     // optional; false → не штрафуется как FN
        }
      ],

      "false_positive_patterns": [
        {
          "source_var": "realm",         // matched fuzzy (substring, либо
          "sink_var": "setClientNote",   //  source_pattern/sink_pattern regex)
          "reason": "internal session setter — не выводится наружу"
        }
      ]
    }
  }
}
```

Поля `true_positives` и `false_positive_patterns` независимы:
- цепочки, попавшие в TP → засчитываются как True Positive;
- остальные, попавшие в FP-паттерн → False Positive;
- всё прочее → **unclassified** (=кандидаты на 0-day, ручной просмотр).

## Как добавить новый проект

```bash
mkdir tests/fixtures/real_world/<project>
# Скопируйте/положите .java фикстуры (только файлы, на которых вы
# планируете запускать оценку — не весь проект!).

$EDITOR tests/fixtures/real_world/<project>/ground_truth.json

# Структурная валидация (без запуска LLM):
pytest tests/unit/test_real_world_fixtures.py -v

# Прогон только этого проекта (отчёты пишутся в evaluation/<project>/):
python scripts/evaluate.py --project <project>

# Все проекты сразу + агрегированная таблица:
python scripts/evaluate.py --all-projects

# Сравнение baseline vs after:
python scripts/evaluate.py --diff \
    evaluation/<project>/baseline.json \
    evaluation/<project>/after.json
```

## Поиск 0-day

`unclassified` цепочки — то, чего нет ни в TP-списке, ни в известных FP. На
**незнакомом** проекте именно этот столбец интересует ресёрчера: высокая
confidence + USER_INPUT/EXTERNAL_DATA источник + DIRECT_EXECUTION/
OUTPUT_RENDERING сток = живой кандидат.

Практический workflow для нового кодовой базы:

1. Положить файлы интереса в `tests/fixtures/real_world/<project>/`,
   разметить только заведомо известные FP в `false_positive_patterns`
   (без `true_positives` пока их не подтвердили).
2. Прогнать `python scripts/evaluate.py --project <project> --baseline`.
3. Каждую цепочку с conf ≥ 0.7 в `unclassified` проверить руками.
   Подтверждённые уязвимости — переехать в `true_positives` (с описанием),
   false-paths — в `false_positive_patterns`. Это превращает прогон в
   воспроизводимый regression-тест для будущих изменений ядра.
