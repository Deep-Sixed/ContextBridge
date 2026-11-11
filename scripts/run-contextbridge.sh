#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${MCP_AUTH_TOKEN:?Set MCP_AUTH_TOKEN using a secret manager}"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m contextbridge.knowledge.gateway --config "$ROOT/configs/contextbridge.yaml"
