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
| `LLM_MODEL` | Название модели | строка | `gpt-4-turbo` (OpenAI) / `llama3:latest` (Ollama) |
| `OLLAMA_BASE_URL` | URL сервера Ollama | URL | `http://localhost:11434` |

### Поиск путей

| Переменная | Описание | Значения | По умолчанию |
|-----------|----------|----------|-------------|
| `PATHFINDING_ALGORITHM` | Алгоритм поиска путей | `astar`, `bfs` | `astar` |
| `USE_SEMANTIC_HEURISTIC` | Семантическая эвристика в A* (CodeBERT) | `true`, `false` | `true` |
| `MAX_PATH_LENGTH` | Максимальная длина пути | целое число | `15` |
| `USE_JOERN` | Использовать Joern для PDG | `true`, `false` | `false` |

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
| `LOG_FILE` | Путь к лог-файлу | путь | `data/vtc.log` |

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
```
