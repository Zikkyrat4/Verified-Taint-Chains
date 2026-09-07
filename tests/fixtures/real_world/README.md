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

## Режимы оценки

| Режим | Когда | Что вызывается |
|---|---|---|
| `single-file` (default) | `ground_truth.json` без `mode` или `mode != "project"` | `pipeline.run(file)` поштучно для каждого `files["<rel>"]`. Кросс-файловые потоки не отслеживаются. |
| `project` | `ground_truth.json` содержит `"mode": "project"` | `pipeline.run_project(all .java files)` один раз; цепочки атрибутируются к `files["<rel>"]` по `chain.sink.file`. Кросс-файловые TP заявляются через `source_file`/`sink_file` в записи TP. |

Каждый single-file проект — это **CVE, обнаружимая по одному файлу**: source, sink и
семантика sink'а локально присутствуют в коде. Если эксплойт требует знания о
другой библиотеке (Hibernate Validator EL-evaluation), о вызывающей стороне
конструктора или о цепочке через другой класс — кейс **не входит** в
single-file набор; такие сценарии измеряются project-режимом.

## CWE-coverage matrix

7 single-file файлов + 1 project-mode фикстура, 5 классов уязвимостей.
Источник CVE — [`cwe-bench-java`](https://github.com/iris-sast/cwe-bench-java),
ранее размеченные Keycloak-кейсы, и
[WebGoat](https://github.com/WebGoat/WebGoat) (GPL-2.0-or-later) для project-режима.

### Single-file evaluation

| CWE | Класс | Project | File |
|-----|-------|---------|------|
| CWE-022 | Path Traversal | keycloak | `CVE-2022-3782/RedirectUtils.java` |
| CWE-078 | OS Command Injection | jenkins-docker-commons | `CVE-2022-20617/DockerRegistryEndpoint.java` |
| CWE-078 | OS Command Injection | jenkins-perfecto | `CVE-2020-2261/PerfectoBuildWrapper.java` |
| CWE-079 | XSS | keycloak | `CVE-2022-4361/SamlService.java` |
| CWE-079 | XSS | jspwiki | `CVE-2019-10076/LinkToTag.java` |
| CWE-502 | Unsafe Deserialization | keycloak | `SerializedBrokeredIdentityContext.java` |
| CWE-601 | Open Redirect | keycloak | `OIDCLoginProtocol.java` |

### Project-mode evaluation

| CWE | Класс | Project | Files | Что измеряется |
|-----|-------|---------|-------|---|
| CWE-022 | Path Traversal / Zip Slip | webgoat | `pathtraversal/*.java` (7 файлов) | TP-1/TP-2 — source в подклассе, sink в наследованном методе базы (кросс-файл). TP-3/TP-4 — single-file как контроль. ProfileUploadFix — known-FP (санитайзер). |

**Кейсы, исключённые из single-file набора по принципиальным причинам:**

| Бывший CVE | Причина исключения |
|---|---|
| `cron-utils/CVE-2021-41269` (EL injection) | Sink — `throw new IllegalArgumentException(format, expression)` — становится опасным только из-за Hibernate Validator EL-evaluation в **другой** библиотеке. Single-file LLM этого не видит. |
| `spark/CVE-2018-9159` (path traversal) | Source — параметр конструктора `public ClassPathResource(String path, …)`. USER_INPUT-attribution требует знания вызывающей стороны (entry point) в другом файле. |
| `spring-framework/CVE-2022-22965` (Spring4Shell) | Эксплойт цепляется через `ClassLoader` → `protectionDomain` → Tomcat `AccessLogValve` — несколько классов в разных пакетах. Принципиально вне single-file scope. |

## Методология детекции (для защиты — train/test leakage)

Эталонные `ground_truth.json` детектор **не видит**: они подаются только
`src/evaluation/` для подсчёта TP/FP/FN/Unclassified *после* прогона
пайплайна. Вход Stage 1 — исключительно `.java`-файл.

«Что является опасной операцией» определяется так:

1. **Capability-промпт, не чек-лист.** Промпты Stage 1
   (`src/stage1_llm_inference/prompt_templates.py`) описывают source/sink
   через *способность* (операция интерпретирует/исполняет/передаёт/рендерит
   данные так, что атакующий-контролируемое значение нарушает CIA).
   Перечень категорий помечен «illustrative, NOT exhaustive» — это
   априорный калибровочный набор по CWE/OWASP, **не** итеративно
   подгонявшийся под FN бенчмарка. LLM рассуждает над произвольным кодом, а
   не сверяется со списком.
2. **Открытый словарь типов.** Модель выдаёт свободный
   `vulnerability_type` + `cwe_id` + обоснование. Детерминированный
   пост-слой (`_infer_vulnerability_type`) нормализует строку в
   канонический enum **только** для сопоставления с ground truth и выбора
   шаблона Stage 4 — никогда для самого детекта и никогда не перебивая
   уверенный ярлык LLM. Нераспознанный класс → `OTHER` (не молчаливый
   `SQL_INJECTION`), CWE берётся от LLM → новый/0-day класс остаётся видимым
   и попадает в **Unclassified**, а не теряется.
3. **Два явно разных уровня охвата.** Режим `targeted` отправляет LLM только
   методы с общими security-boundary/API признаками и поэтому может пропустить
   незнакомый API. Режим `exhaustive` отправляет все структурно-нетривиальные
   методы и стоит дороже. Backend и режим охвата записываются в отчёт.
4. **Контроль утечки.** В ядре `src/` нет имён проектов, CVE, классов или
   переменных из этого benchmark. Статический baseline использует только
   общие Java/security capabilities и никогда не включается неявно в `llm`.

**Известное ограничение (озвучивать первым):** покрываемые *классы*
фиксированы калибровочной таксономией; принципиально новый класс выявится
как `OTHER` с CWE-обоснованием (видим, но без специализированного шаблона).
Это ограничение signature-guided LLM-подхода, не «подгонка под ответ».
Контроль leakage: расширение таксономии формулируется как CWE-класс, не как
инстанс из фикстуры; held-out проверка отсутствия FP-регресса на проектах,
где правило не должно срабатывать.

## Ограничения графа потоков (Stage 2 — честно для защиты)

Stage 2 строит граф приближённо (регекс-эвристики поверх AST), без полного
межпроцедурного анализа. Отсюда воспроизводимые пропуски, которые **не**
маскируются подгонкой ground truth:

1. **Кросс-файловый мост — по совпадению имени переменной.** Есть два моста:
   (1) одно имя является источником в файле A и стоком в файле B; (2)
   *parameter pass-through* — источник `var` в A соединяется с одноимённым
   узлом `B:var`, который течёт дальше (out-degree > 0). Мост (2) ловит
   наследование/делегирование: подкласс передаёт `fullName` в
   `super.execute(file, fullName, ..)`, а базовый метод строит
   `new File(dir, fullName)` (присвоенный `uploadedFile`) — путь
   `Sub:fullName → Base:fullName → Base:uploadedFile`. **Остаточное
   ограничение:** если подкласс передаёт выражение **инлайн** и в
   *разноимённый* параметр (`super.execute(file, file.getOriginalFilename(),
   ..)`), именованного узла `fullName` в подклассе нет, а позиционной
   привязки аргументов к формальным параметрам (`file → fullName`) мост не
   делает — это уже полноценный межпроцедурный анализ. Старый флаг
   `expected_realistic: false` сохраняется как описание сложности, но такие
   кейсы всё равно входят в основной recall и становятся FN при пропуске.
2. **`source_var == sink_var` в одном scope недетектируем как self-loop.**
   Узлы графа ключуются по имени переменной, поэтому если заражённый ввод
   *сам* является аргументом стока без промежуточного присваивания (источник и
   сток — одна переменная в одном файле), путь вырождается в один узел и
   отбрасывается фильтром self-loop (`len(path_nodes) <= 1`). В ground truth
   такой поток описывается через переменную-приёмник (`new File(dir, id)`,
   присвоенный `catPicture` → `sink_var: "catPicture"`, а не `"id"`): источник
   и сток обязаны быть **разными** узлами. Это решение моделирования, а не хак.
3. **Шум на больших методах с десериализацией.** На файлах вроде SAML-сервиса
   (XML-десериализация → масса производных переменных) граф порождает сотни
   цепочек; целевой поток тонет в **Unclassified**. Точность по таким файлам
   ограничена отсутствием scope-разделения переменных с одинаковым именем в
   разных методах (они схлопываются в один узел).

## ground_truth.json — схема

```jsonc
{
  "mode": "project",                     // optional; "project" → pipeline.run_project, иначе per-file
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
          "source_file": "Foo.java",     // optional; точный относительный suffix source path
          "sink_file":   "Bar.java",     // optional; точный относительный suffix sink path
          "source_line": 215,            // 1-indexed; 0 = unknown
          "sink_line": 303,
          "vuln_type": "xss",            // xss | sql_injection | command_injection | path_traversal | xxe | ssrf | deserialization | open_redirect | code_injection
          "description": "что именно за поток и почему это уязвимость",
          "expected_realistic": true     // legacy metadata о сложности; метрики не меняет
        }
      ],

      "false_positive_patterns": [
        {
          "source_var": "realm",         // точное canonical identifier match
          "sink_var": "setClientNote",   // regex задаётся только через *_pattern
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
- всё прочее → **unclassified** (=кандидаты на ручной просмотр), но в
  основной precision они также считаются ложными срабатываниями.

## Как добавить новый проект

```bash
mkdir tests/fixtures/real_world/<project>
# Скопируйте/положите .java фикстуры (только файлы, на которых вы
# планируете запускать оценку — не весь проект!).

$EDITOR tests/fixtures/real_world/<project>/ground_truth.json

# Структурная валидация (без запуска LLM):
pytest tests/unit/test_real_world_fixtures.py -v

# Прогон только этого проекта (отчёты пишутся в evaluation/<project>/):
vtc evaluate --project <project>

# Все проекты сразу + агрегированная таблица:
vtc evaluate --all-projects

# Сравнение baseline vs after:
vtc evaluate --diff \
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
2. Прогнать `vtc evaluate --project <project> --baseline`.
3. Каждую цепочку с conf ≥ 0.7 в `unclassified` проверить руками.
   Подтверждённые уязвимости — переехать в `true_positives` (с описанием),
   false-paths — в `false_positive_patterns`. Это превращает прогон в
   воспроизводимый regression-тест для будущих изменений ядра.
