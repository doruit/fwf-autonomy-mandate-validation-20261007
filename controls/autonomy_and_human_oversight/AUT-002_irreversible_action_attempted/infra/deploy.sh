#!/usr/bin/env bash
set -euo pipefail
CONTROL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
"${CONTROL_ROOT}/../../../.venv/bin/python" "${CONTROL_ROOT}/infra/deploy.py" "$@"