# Использование

## Команда анализа

```bash
vtc analyze [ОПЦИИ] ФАЙЛ
```

Анализирует Java-файл на наличие уязвимостей.

### Аргументы

| Аргумент | Описание |
|----------|----------|
| `ФАЙЛ` | Путь к Java-файлу для анализа |

### Опции

| Опция | Сокращение | Описание |
|-------|-----------|----------|
| `--output PATH` | `-o` | Сохранить результат в JSON-файл |
| `--verification-level` | — | Уровень верификации: `cfg`, `symbolic`, `both` |
| `--pathfinding-algorithm` | — | Алгоритм поиска: `astar`, `bfs` |
| `--llm-provider` | — | LLM-провайдер: `openai`, `ollama` |
| `--llm-model` | — | Название LLM-модели |
| `--verbose` | `-v` | Подробный вывод (пути, объяснения) |

Опции CLI имеют приоритет над настройками из `.env`.

## Примеры

### Базовый анализ

```bash
vtc analyze code.java
```

Вывод:
```
======================================================================
RESULTS
======================================================================
Sources found: 26
Sinks found: 19
Chains discovered: 43
Chains verified: 21
Verification rate: 48.8%
Explanations generated: 20

======================================================================
VULNERABILITIES FOUND: 21
======================================================================

[1] sql_injection
  Source: password (line 84)
  Sink: password (line 84)
  Confidence: 90.0%
  Verification: verified
```

### Подробный вывод

```bash
vtc analyze code.java -v
```

Добавляет для каждой уязвимости:
- Длину и узлы пути
- Описание (почему уязвимо)
- Рекомендации по исправлению
- Severity и CWE-идентификатор

### Сохранение в JSON

```bash
vtc analyze code.java -o results.json
```

### Использование Ollama

```bash
vtc analyze code.java --llm-provider ollama --llm-model llama3.2:latest
```

### Полная верификация

```bash
vtc analyze code.java --verification-level both
```

## Формат JSON-вывода

```json
{
  "file": "code.java",
  "total_chains": 43,
  "metrics": {
    "sources_found": 26,
    "sinks_found": 19,
    "chains_found": 43,
    "chains_verified": 21,
    "verification_rate": 0.49,
    "explanations_generated": 20
  },
  "vulnerabilities": [
    {
      "id": "password_to_password_123",
      "type": "sql_injection",
      "source": {
        "variable": "password",
        "line": 84,
        "confidence": 1.0
      },
      "sink": {
        "variable": "password",
        "line": 84,
        "confidence": 0.8
      },
      "path": ["password"],
      "confidence": 0.9,
      "verification": "verified",
      "explanation": {
        "why_vulnerable": "Переменная password конкатенируется в SQL-запрос...",
        "how_to_fix": "Использовать PreparedStatement...",
        "example_fix": "pstmt.setString(1, password);",
        "severity": "CRITICAL",
        "cwe_id": "CWE-89"
      }
    }
  ]
}
```

### Поля vulnerability

| Поле | Тип | Описание |
|------|-----|----------|
| `id` | string | Уникальный идентификатор цепочки |
| `type` | string | Тип уязвимости (`sql_injection`, `xss`, `command_injection`, `path_traversal`, `xxe`, `ssrf`) |
| `source` | object | Источник: переменная, строка, уверенность |
| `sink` | object | Сток: переменная, строка, уверенность |
| `path` | array | Список переменных по пути от source к sink |
| `confidence` | float | Общая уверенность (0.0–1.0) |
| `verification` | string | Статус верификации: `verified`, `false`, `unverifiable` |
| `explanation` | object | Объяснение (при наличии) |

### Поля explanation

| Поле | Тип | Описание |
|------|-----|----------|
| `why_vulnerable` | string | Почему код уязвим |
| `how_to_fix` | string | Рекомендации по исправлению |
| `example_fix` | string | Пример безопасного кода |
| `severity` | string | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `cwe_id` | string | CWE-идентификатор (например `CWE-89`) |
