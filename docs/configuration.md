# Конфигурация

Основные настройки хранятся в типизированном `vtc.toml`. Секреты (например,
`OPENAI_API_KEY`) остаются в `.env` или в окружении процесса.

```bash
# Создать полный документированный шаблон ./vtc.toml
vtc config init

# Проверить TOML, типы, диапазоны и необходимые секреты
vtc config validate

# Увидеть эффективные значения; API-ключ никогда не печатается
vtc config show
vtc config show --sources

# Выбрать другой файл или профиль для любой команды
vtc --config ./configs/ci.toml --profile thorough analyze src/
```

Порядок приоритета: встроенные значения → базовые секции `vtc.toml` → выбранный
профиль → `.env` → переменные окружения процесса → параметры команды. Поэтому
существующие deployment-конфигурации на ENV продолжат работать.

Файл ищется в следующем порядке: `--config` / `VTC_CONFIG`, `./vtc.toml`, затем
`~/.config/vtc/config.toml` (или `$XDG_CONFIG_HOME/vtc/config.toml`). Профиль
задается через `--profile`, `VTC_PROFILE` или верхнеуровневый `profile` в TOML.
Неизвестные секции и ключи считаются ошибкой, чтобы опечатка не меняла результат
анализа молча. Готовый пример находится в [`vtc.example.toml`](../vtc.example.toml).

## Профили

Профиль переопределяет только указанные значения:

```toml
version = 1
profile = "balanced"

[analysis]
backend = "llm"
llm_mode = "targeted"

[performance]
max_concurrent_llm_requests = 5

[profiles.thorough.analysis]
llm_mode = "exhaustive"

[profiles.fast.analysis]
fast_prefilter = true

[profiles.fast.performance]
max_concurrent_llm_requests = 2
```

`thorough` подходит для честного полного benchmark-прогона. `fast_prefilter` в
профиле `fast` агрессивно исключает файлы и поэтому не должен использоваться
для публикации итоговых метрик.

## Настройка LLM-провайдера

### OpenAI

```toml
[llm]
provider = "openai"
model = "gpt-4-turbo"
```

Ключ задается отдельно: `OPENAI_API_KEY=sk-...` в `.env` или окружении.

Модель по умолчанию: `gpt-4-turbo`. Можно указать любую модель OpenAI API (`gpt-4o`, `gpt-3.5-turbo` и т.д.).

### Ollama

```toml
[llm]
provider = "ollama"
model = "llama3.2:latest"

[ollama]
base_url = "http://localhost:11434"
```

API-ключ не требуется. Сервер Ollama должен быть запущен локально. URL сервера по умолчанию `http://localhost:11434`, можно изменить:

Подходящие модели: `llama3.2:latest`, `mistral:latest`, `codellama:latest`, `deepseek-coder:latest`.

## Переменные окружения

ENV — совместимый override-слой над одноименными полями TOML. Полная структура
TOML и значения по умолчанию доступны через `vtc config init`; ниже приведено
соответствие для существующих окружений.

### LLM

| Переменная | Описание | Значения | По умолчанию |
|-----------|----------|----------|-------------|
| `LLM_PROVIDER` | LLM-провайдер | `openai`, `ollama` | `openai` |
| `OPENAI_API_KEY` | API-ключ OpenAI | строка | — (обязателен для OpenAI) |
| `OPENAI_TIMEOUT` | Таймаут одного OpenAI-запроса, сек. | число > 0 | `300` |
| `OPENAI_JSON_MODE` | Использовать `response_format=json_object` | `true`, `false` | `true` |
| `OPENAI_THINKING` | Управление reasoning совместимого endpoint | `enabled`, `disabled` | `disabled` для `glm-*` |
| `LLM_MAX_RETRIES` | Максимум попыток после временной ошибки/пустого ответа | целое >= 1 | `2` |
| `LLM_MAX_TOKENS` | Максимальный размер ответа LLM | целое > 0 | `4000` |
| `LLM_TRUNCATION_MAX_TOKENS` | Верхний предел ответа для повтора одиночного усеченного batch | целое >= `LLM_MAX_TOKENS` | `16000` |
| `LLM_BATCH_MAX_CHARS` | Максимальный размер непрерывного batch методов (`0` отключает batching) | целое >= 0 | `8000` |
| `ANALYSIS_BACKEND` | Генератор source/sink: только LLM / статический baseline / явное объединение | `llm`, `static`, `hybrid` | `llm` |
| `LLM_ANALYSIS_MODE` | Охват LLM: релевантные методы / все обнаруженные методы | `targeted`, `exhaustive` | `targeted` |
| `LLM_MODEL` | Название модели | строка | `gpt-4-turbo` (OpenAI) / `llama3:latest` (Ollama) |
| `OLLAMA_BASE_URL` | URL сервера Ollama | URL | `http://localhost:11434` |
| `OLLAMA_MIN_NUM_PREDICT` | Минимальный output budget Ollama | целое > 0 | `4096` |
| `OLLAMA_SEED` | Seed; `none` отключает фиксацию | целое, `none` | `42` |
| `OLLAMA_JSON_FORMAT` | Grammar-constrained JSON в Ollama | `true`, `false` | `true` |

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

Если batch не помещается в `LLM_MAX_TOKENS`, он рекурсивно делится по границам
методов. Для одного неделимого метода output budget увеличивается ступенчато,
но не выше `LLM_TRUNCATION_MAX_TOKENS`. Окончательная ошибка остается execution
error и не превращается в отрицательную prediction.

### Параллелизм

| Переменная | Описание | Значения | По умолчанию |
|-----------|----------|----------|-------------|
| `MAX_CONCURRENT_FILES` | Параллельно анализируемые файлы проекта | целое > 0 | `4` |
| `MAX_CONCURRENT_FUNCTIONS` | Параллельные LLM-запросы функций одного файла | целое > 0 | `2` |
| `MAX_CONCURRENT_LLM_REQUESTS` | Жесткий общий предел запросов к LLM по всем файлам | целое > 0 | `5` |

Первые две настройки управляют планированием задач, но их произведение не
увеличивает нагрузку на endpoint выше `MAX_CONCURRENT_LLM_REQUESTS`. CLI-флаг
`--max-concurrent` у `analyze`/`sinks` и
`--max-concurrent-llm-requests` у `benchmark run` переопределяют именно этот
глобальный предел.

### Поиск путей

| Переменная | Описание | Значения | По умолчанию |
|-----------|----------|----------|-------------|
| `PATHFINDING_ALGORITHM` | Алгоритм поиска путей | `astar`, `bfs` | `astar` |
| `USE_SEMANTIC_HEURISTIC` | Использовать семантическую эвристику в A* | `true`, `false` | `true` |
| `VTC_USE_CODEBERT` | Загрузить CodeBERT вместо быстрой детерминированной эвристики | `true`, `false` | `false` |
| `MAX_PATH_LENGTH` | Максимальная длина пути | целое число | `15` |
| `MAX_CANDIDATE_CHAINS` | Предел сохраняемых кандидатов; переполнение помечается в metrics | целое > 0 | `10000` |
| `USE_JOERN` | Использовать Joern для PDG | `true`, `false` | `false` |
| `LLM_GRAPH_ENRICHMENT_ENABLED` | Добавлять спекулятивные LLM-рёбра поверх AST | `true`, `false` | `false` |

### Верификация

| Переменная | Описание | Значения | По умолчанию |
|-----------|----------|----------|-------------|
| `VERIFICATION_LEVEL` | Уровень верификации | `cfg`, `symbolic`, `both` | `cfg` |
| `SYMBOLIC_TIMEOUT` | Таймаут символьного выполнения (сек.) | целое число | `60` |
| `VERIFICATION_ENABLED` | Включить верификацию | `true`, `false` | `true` |

`MAX_CANDIDATE_CHAINS` не обрезает результат молча: при превышении анализ
завершается явной resource-limit ошибкой. В пользовательские findings попадают
только цепочки `verified`. Цепочки `unverifiable` и `false` возвращаются
отдельно и не учитываются как обнаруженные уязвимости. Внешние benchmark-ы
требуют `VERIFICATION_ENABLED=true`.

### Анализ

| Переменная | Описание | Значения | По умолчанию |
|-----------|----------|----------|-------------|
| `MIN_CONFIDENCE` | Минимальный порог уверенности | 0.0–1.0 | `0.6` |
| `MAX_FILES` | Ограничение файлов; `0` без ограничения | целое >= 0 | `0` |
| `VTC_FAST_PREFILTER` | Агрессивно исключать файлы без известных паттернов | `true`, `false` | `false` |

`VTC_FAST_PREFILTER=true` предназначен для быстрых диагностических запусков и
может снижать recall. Для честного benchmark-прогона оставляйте `false`.

### Кэш и benchmark-и

| Переменная | Описание | По умолчанию |
|-----------|----------|-------------|
| `VTC_CACHE_ENABLED` | Включить постоянный Stage 1 cache | `true` |
| `VTC_CACHE_DIR` | Явный каталог cache | `<source>/.vtc-cache` |
| `VTC_BENCHMARK_DIR` | Каталог внешних benchmark-данных | `.vtc-benchmarks` |

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

## Пример минимального `.env`

```env
# Секрет хранится вне vtc.toml
OPENAI_API_KEY=sk-...

# Необязательные overrides для конкретного хоста
# OPENAI_BASE_URL=http://localhost:8000/v1
# MAX_CONCURRENT_LLM_REQUESTS=5
```
