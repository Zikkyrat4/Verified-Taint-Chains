# Тестирование

## Запуск тестов

```bash
# Все тесты
pytest

# С покрытием кода
pytest --cov=src

# Только модульные тесты
pytest tests/unit/

# Только интеграционные тесты
pytest tests/integration/

# Конкретный файл
pytest tests/unit/test_base_client.py

# Конкретный тест
pytest tests/unit/test_base_client.py::TestBaseLLMClient::test_chat_with_json_prompt_success

# С подробным выводом
pytest -v
```

## Структура тестов

```
tests/
├── unit/                           # Модульные тесты
│   ├── test_models.py              # Pydantic-модели
│   ├── test_config.py              # Конфигурация
│   ├── test_base_client.py         # Базовый LLM-клиент
│   ├── test_openai_client.py       # OpenAI-клиент
│   ├── test_ollama_client.py       # Ollama-клиент
│   ├── test_specification_extractor.py  # Извлечение спецификаций
│   ├── test_ast_parser.py          # AST-парсер
│   ├── test_prompt_templates.py    # Шаблоны промптов
│   ├── test_graph_builder.py       # Построение графа
│   ├── test_astar_search.py        # A*-поиск
│   ├── test_bfs_pathfinder.py      # BFS-поиск
│   ├── test_cfg_verifier.py        # CFG-верификатор
│   ├── test_symbolic_executor.py   # Символьное выполнение
│   ├── test_verification_engine.py # Движок верификации
│   ├── test_explanation_generator.py # Генератор объяснений
│   ├── test_templates.py           # Шаблоны уязвимостей
│   ├── test_pipeline.py            # Оркестратор
│   └── test_pipeline_main.py       # CLI
├── integration/                    # Интеграционные тесты
│   ├── test_end_to_end.py          # End-to-end пайплайн
│   ├── test_stage1_integration.py  # Интеграция Этапа 1
│   └── test_context_aware_prompts.py # Контекстные промпты
├── performance/                    # Тесты производительности
│   └── test_performance.py         # Бенчмарки
└── fixtures/                       # Тестовые данные
    ├── vulnerable_code/            # Java-файлы с уязвимостями
    ├── safe_code/                  # Безопасные Java-файлы
    └── ground_truth.json           # Эталонные результаты
```

## Тестовые фикстуры

### Уязвимый код (`tests/fixtures/vulnerable_code/`)

| Файл | Уязвимости |
|------|-----------|
| `sql_injection_basic.java` | SQL Injection (базовая конкатенация) |
| `sql_injection_complex.java` | SQL Injection (StringBuilder, множественные точки) |
| `sql_injection_long_path.java` | SQL Injection (длинный путь, 5+ узлов) |
| `sql_injection_control_flow.java` | SQL Injection (через условные ветвления) |
| `xss_reflected.java` | XSS (отражённый) |
| `xss_with_partial_sanitization.java` | XSS (неполная санитизация) |
| `command_injection.java` | Command Injection |
| `path_traversal.java` | Path Traversal |
| `xxe_injection.java` | XXE |
| `ssrf_attack.java` | SSRF |
| `multiple_vulnerabilities.java` | Смешанные уязвимости |

### Безопасный код (`tests/fixtures/safe_code/`)

| Файл | Что проверяет |
|------|-------------|
| `sql_safe_prepared_statement.java` | PreparedStatement |
| `xss_safe_encoding.java` | HTML-кодирование |
| `command_safe_array.java` | Безопасное выполнение команд |
| `path_safe_validation.java` | Валидация путей |

### Эталонные результаты (`ground_truth.json`)

Содержит ожидаемые sources, sinks и цепочки для каждого тестового файла. Используется для расчёта precision, recall и F1-score в end-to-end тестах.

## Линтинг и форматирование

```bash
# Проверка стиля
ruff check src tests
black --check src tests

# Автоформатирование
black src tests

# Проверка типов
mypy src
```
