# VTC — Verified Taint Chains

LLM-first инструмент анализа безопасности Java-кода. LLM обнаруживает границы taint-потока, после чего детерминированные этапы строят и верифицируют цепочки распространения данных (taint chains).

## Как это работает

Анализ выполняется в 4 этапа:

1. **LLM-инференс** — LLM анализирует код и определяет источники небезопасных данных (sources) и опасные операции (sinks)
2. **Поиск путей** — строится граф потоков данных, алгоритмом A* или BFS ищутся пути от sources к sinks
3. **Верификация** — найденные цепочки проверяются через анализ потока управления (CFG) и символьное выполнение (Z3)
4. **Объяснение** — для подтверждённых уязвимостей генерируется описание, рекомендации по исправлению и CWE-классификация

### Поддерживаемые типы уязвимостей

- SQL Injection (CWE-89)
- XSS (CWE-79)
- Command Injection (CWE-78)
- Path Traversal (CWE-22)
- XXE (CWE-611)
- SSRF (CWE-918)
- Unsafe Deserialization (CWE-502)
- Code Injection (CWE-94)
- Open Redirect (CWE-601)

## Установка

```bash
# Клонировать репозиторий
git clone <repository-url>
cd verified-taint-chains

# Создать виртуальное окружение
python -m venv venv
source venv/bin/activate

# Установить зависимости
pip install -e ".[dev]"

# Скопировать и настроить конфигурацию
cp .env.example .env
# Отредактировать .env — указать LLM-провайдер и API-ключи
```

### Требования

- Python >= 3.10
- Для OpenAI: API-ключ (`OPENAI_API_KEY`)
- Для Ollama: запущенный сервер Ollama с загруженной моделью

## Использование

```bash
# Базовый анализ
vtc analyze code.java

# Сохранить результат в JSON
vtc analyze code.java -o results.json

# Подробный вывод с объяснениями
vtc analyze code.java -v

# Использовать Ollama вместо OpenAI
vtc analyze code.java --llm-provider ollama --llm-model llama3.2:latest

# Выбрать уровень верификации
vtc analyze code.java --verification-level both

# Выбрать алгоритм поиска путей
vtc analyze code.java --pathfinding-algorithm bfs
```

Полный список команд: `vtc --help`; опции анализа: `vtc analyze --help`.

### Оценка на реальных CVE

Набор фикстур с реальными уязвимостями лежит в `tests/fixtures/real_world/`
(5 проектов). Запуск оценочного прогона:

```bash
# Основной LLM-прогон; отдельная метка не перезаписывает after.*
vtc evaluate --project keycloak --backend llm --phase-label llm-honest

# Все проекты сразу + агрегированная таблица
vtc evaluate --all-projects --backend llm --phase-label llm-honest

# Принудительно обновить кэш извлечённых LLM-спецификаций
vtc evaluate --all-projects --backend llm \
  --phase-label llm-honest --refresh-specs

# Статический baseline запускается и публикуется только отдельно
vtc evaluate --all-projects --backend static --phase-label static-honest

# Повторный запуск той же команды использует кэш LLM-спецификаций
```

Добавление нового проекта = новая директория под
`tests/fixtures/real_world/<project>/` с `ground_truth.json` и
.java-файлом(-ами). Схема и список покрытых CWE:
[`tests/fixtures/real_world/README.md`](tests/fixtures/real_world/README.md).

## Конфигурация

Настройки загружаются из файла `.env`. Основные параметры:

| Переменная | Значение | По умолчанию |
|-----------|----------|-------------|
| `LLM_PROVIDER` | `openai` или `ollama` | `openai` |
| `OPENAI_API_KEY` | API-ключ OpenAI | — |
| `OPENAI_TIMEOUT` | Таймаут одного OpenAI-запроса, сек. | `60` |
| `OPENAI_JSON_MODE` | Запрашивать структурированный JSON-ответ | `true` |
| `OPENAI_THINKING` | `enabled`/`disabled`; для `glm-*` автоматически `disabled` | auto |
| `LLM_MAX_RETRIES` | Максимум попыток LLM-запроса | `2` |
| `LLM_BATCH_MAX_CHARS` | Максимальный размер файлового LLM-batch | `8000` |
| `ANALYSIS_BACKEND` | `llm`, `static` или `hybrid`; метрики режимов не смешиваются | `llm` |
| `LLM_ANALYSIS_MODE` | `targeted` или `exhaustive` | `targeted` |
| `MAX_CONCURRENT_FUNCTIONS` | Параллельные функции внутри файла | `2` |
| `LOG_LEVEL` | Уровень stderr и файлового лога | `INFO` |
| `LOG_FILE` | Путь к логу; `off` отключает файл | `~/.local/state/vtc/vtc.log` |
| `LLM_MODEL` | Название модели | `gpt-4-turbo` / `llama3:latest` |
| `PATHFINDING_ALGORITHM` | `astar` или `bfs` | `astar` |
| `VERIFICATION_LEVEL` | `cfg`, `symbolic` или `both` | `cfg` |
| `MIN_CONFIDENCE` | Порог уверенности (0.0–1.0) | `0.5` |
| `MAX_PATH_LENGTH` | Макс. длина пути | `15` |

Подробнее: [docs/configuration.md](docs/configuration.md)

В режиме по умолчанию `ANALYSIS_BACKEND=llm` статические эвристики не создают
`source` или `sink`. `static` предназначен только для отдельного baseline,
`hybrid` — для явно помеченного ablation-эксперимента.

## Структура проекта

```
src/
├── core/                       # Pydantic-модели, конфигурация
├── stage1_llm_inference/       # LLM-клиенты, парсер, промпты
├── stage2_path_discovery/      # Граф, A*, BFS, Joern
├── stage3_verification/        # CFG-верификатор, символьное выполнение
├── stage4_explanation/         # Шаблоны объяснений, генератор
├── pipeline/                   # Оркестратор, CLI
└── utils/                      # Логирование, утилиты
tests/
├── unit/                       # Модульные тесты
├── integration/                # Интеграционные тесты
├── performance/                # Тесты производительности
└── fixtures/                   # Тестовые Java-файлы
docs/                           # Документация
```

## Разработка

```bash
# Запуск тестов
pytest

# Тесты с покрытием
pytest --cov=src

# Линтинг
ruff check src tests
black --check src tests

# Проверка типов
mypy src
```

## Документация

- [Архитектура](docs/architecture.md) — описание 4-этапного пайплайна
- [Конфигурация](docs/configuration.md) — все параметры настройки
- [Использование](docs/usage.md) — CLI, формат вывода, примеры
- [Тестирование](docs/testing.md) — запуск тестов, фикстуры

## Лицензия

MIT License
