#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${CONTEXTBRIDGE_COMPUTER_TOKEN:?Set CONTEXTBRIDGE_COMPUTER_TOKEN using a secret manager}"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m contextbridge.computer --config "${CONTEXTBRIDGE_COMPUTER_CONFIG:-$ROOT/configs/computer.yaml}"
