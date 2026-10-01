#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="/opt/Verified-Taint-Chains"
BENCHMARK_CHECKOUT="$PROJECT_ROOT/.vtc-benchmarks/upstream/cwe-bench-java"

cd "$PROJECT_ROOT"
set -a
source .env
set +a

export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0=safe.directory
export GIT_CONFIG_VALUE_0="$BENCHMARK_CHECKOUT"

exec venv/bin/vtc benchmark run cwe-bench-java \
  --backend llm \
  --llm-analysis-mode exhaustive \
  --max-concurrent-llm-requests 5 \
  --phase-label glm-5.3-flash-exhaustive-strict-20261001
