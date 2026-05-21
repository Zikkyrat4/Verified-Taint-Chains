# Evaluation artifacts

Snapshot отчёты прогона детектора VTC на real-world фикстурах
(`tests/fixtures/real_world/<project>/`).

Структура:

```
evaluation/
├── README.md
├── <project>/
│   ├── baseline.json   # прогон до правок ядра — точка отсчёта
│   ├── baseline.md
│   ├── after.json      # прогон после правок ядра
│   └── after.md
└── ...
```

Сейчас в наборе 7 проектов: `keycloak`, `spark`, `jenkins-docker-commons`,
`jenkins-perfecto`, `jspwiki`, `cron-utils`, `spring-framework` (см. CWE-coverage
matrix в [`tests/fixtures/real_world/README.md`](../tests/fixtures/real_world/README.md)).
Снятый snapshot пока есть только для `keycloak/` — остальные проекты
прогоняются by-demand командами ниже.

Агрегированные результаты и методология оценки —
[`docs/evaluation.md`](../docs/evaluation.md).

## Воспроизведение

```bash
source venv/bin/activate

# Один проект (отчёты пишутся в evaluation/<project>/after.{json,md}):
python scripts/evaluate.py --project keycloak

# Baseline-снимок (отчёты пишутся в evaluation/<project>/baseline.{json,md}):
python scripts/evaluate.py --project keycloak --baseline

# Все проекты сразу + агрегированная таблица:
python scripts/evaluate.py --all-projects

# Diff:
python scripts/evaluate.py --diff \
    evaluation/keycloak/baseline.json \
    evaluation/keycloak/after.json

# Back-compat (явный путь — output только при --save):
python scripts/evaluate.py \
    --fixtures-dir tests/fixtures/real_world/keycloak \
    --save evaluation/keycloak/after.json \
    --report-md evaluation/keycloak/after.md
```

Baseline регенерируется только при откате правок ядра (`git stash` /
переключение коммита) и повторном запуске на том же наборе фикстур.
