# Конфигурация

Настройки загружаются из файла `.env` в корне проекта. Параметры CLI имеют приоритет над `.env`.

## Настройка LLM-провайдера

### OpenAI

```env
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...
LLM_MODEL=gpt-4-turbo
```

Модель по умолчанию: `gpt-4-turbo`. Можно указать любую модель OpenAI API (`gpt-4o`, `gpt-3.5-turbo` и т.д.).

### Ollama

```env
LLM_PROVIDER=ollama
LLM_MODEL=llama3.2:latest
```

API-ключ не требуется. Сервер Ollama должен быть запущен локально. URL сервера по умолчанию `http://localhost:11434`, можно изменить:

```env
OLLAMA_BASE_URL=http://localhost:11434
```

Подходящие модели: `llama3.2:latest`, `mistral:latest`, `codellama:latest`, `deepseek-coder:latest`.

## Все параметры

### LLM

| Переменная | Описание | Значения | По умолчанию |
|-----------|----------|----------|-------------|
| `LLM_PROVIDER` | LLM-провайдер | `openai`, `ollama` | `openai` |
| `OPENAI_API_KEY` | API-ключ OpenAI | строка | — (обязателен для OpenAI) |
| `OPENAI_TIMEOUT` | Таймаут одного OpenAI-запроса, сек. | число > 0 | `60` |
| `OPENAI_JSON_MODE` | Использовать `response_format=json_object` | `true`, `false` | `true` |
| `OPENAI_THINKING` | Управление reasoning совместимого endpoint | `enabled`, `disabled` | `disabled` для `glm-*` |
| `LLM_MAX_RETRIES` | Максимум попыток после временной ошибки/пустого ответа | целое >= 1 | `2` |
| `LLM_MAX_TOKENS` | Максимальный размер ответа LLM | целое > 0 | `4000` |
| `LLM_BATCH_MAX_CHARS` | Максимальный размер непрерывного batch методов (`0` отключает batching) | целое >= 0 | `8000` |
| `ANALYSIS_BACKEND` | Генератор source/sink: только LLM / статический baseline / явное объединение | `llm`, `static`, `hybrid` | `llm` |
| `LLM_ANALYSIS_MODE` | Охват LLM: релевантные методы / все нетривиальные методы | `targeted`, `exhaustive` | `targeted` |
| `LLM_MODEL` | Название модели | строка | `gpt-4-turbo` (OpenAI) / `llama3:latest` (Ollama) |
| `OLLAMA_BASE_URL` | URL сервера Ollama | URL | `http://localhost:11434` |

`ANALYSIS_BACKEND=llm` не подмешивает статически найденные endpoints. В
`static` LLM-клиент не создаётся и `OPENAI_API_KEY` не требуется. Результаты
`llm`, `static` и `hybrid` следует сохранять и публиковать раздельно.
AST-анализ в LLM-режиме восстанавливает области видимости и проверяет
достижимость выбранных моделью endpoints, но сам не создаёт source/sink.

Спецификации Stage 1 кэшируются по содержимому файла, провайдеру, модели,
backend и режиму охвата. Повторный прогон не вызывает API; для нового ответа
модели используйте `--refresh-specs`. Если endpoint выдерживает нагрузку,
`MAX_CONCURRENT_FUNCTIONS=4` сокращает холодный прогон ценой большего числа
одновременных запросов.

### Параллелизм

| Переменная | Описание | Значения | По умолчанию |
|-----------|----------|----------|-------------|
| `MAX_CONCURRENT_FILES` | Параллельно анализируемые файлы проекта | целое > 0 | `4` |
| `MAX_CONCURRENT_FUNCTIONS` | Параллельные LLM-запросы функций одного файла | целое > 0 | `2` |

### Поиск путей

| Переменная | Описание | Значения | По умолчанию |
|-----------|----------|----------|-------------|
| `PATHFINDING_ALGORITHM` | Алгоритм поиска путей | `astar`, `bfs` | `astar` |
| `USE_SEMANTIC_HEURISTIC` | Использовать семантическую эвристику в A* | `true`, `false` | `true` |
| `VTC_USE_CODEBERT` | Загрузить CodeBERT вместо быстрой детерминированной эвристики | `true`, `false` | `false` |
| `MAX_PATH_LENGTH` | Максимальная длина пути | целое число | `15` |
| `USE_JOERN` | Использовать Joern для PDG | `true`, `false` | `false` |
| `LLM_GRAPH_ENRICHMENT_ENABLED` | Добавлять спекулятивные LLM-рёбра поверх AST | `true`, `false` | `false` |

### Верификация

| Переменная | Описание | Значения | По умолчанию |
|-----------|----------|----------|-------------|
| `VERIFICATION_LEVEL` | Уровень верификации | `cfg`, `symbolic`, `both` | `cfg` |
| `SYMBOLIC_TIMEOUT` | Таймаут символьного выполнения (сек.) | целое число | `60` |
| `VERIFICATION_ENABLED` | Включить верификацию | `true`, `false` | `true` |

### Анализ

| Переменная | Описание | Значения | По умолчанию |
|-----------|----------|----------|-------------|
| `MIN_CONFIDENCE` | Минимальный порог уверенности | 0.0–1.0 | `0.5` |

### Логирование

| Переменная | Описание | Значения | По умолчанию |
|-----------|----------|----------|-------------|
| `LOG_LEVEL` | Уровень логирования | `DEBUG`, `INFO`, `WARNING`, `ERROR` | `INFO` |
| `LOG_FILE` | Путь к лог-файлу; `off` отключает файловый лог | путь или `off` | `~/.local/state/vtc/vtc.log` |

Обе переменные применяются при запуске `vtc analyze`, `vtc sinks` и
`vtc evaluate`. Флаг `-v` у `analyze` и `sinks` переопределяет уровень на
`DEBUG`. Если задан `XDG_STATE_HOME`, путь по умолчанию становится
`$XDG_STATE_HOME/vtc/vtc.log`. Лог-файлы создаются с правами `0600`; сырые
prompt и ответы LLM в них не записываются.

## Пример .env

```env
# LLM
LLM_PROVIDER=ollama
LLM_MODEL=llama3.2:latest

# Поиск путей
PATHFINDING_ALGORITHM=astar
USE_SEMANTIC_HEURISTIC=true
MAX_PATH_LENGTH=15

# Верификация
VERIFICATION_LEVEL=both
SYMBOLIC_TIMEOUT=60

# Анализ
MIN_CONFIDENCE=0.5

# Логирование
LOG_LEVEL=INFO
# LOG_FILE=~/.local/state/vtc/vtc.log
# LOG_FILE=off  # отключить постоянный файловый лог
```
