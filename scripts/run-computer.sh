#!/usr/bin/env bash
# Usage: run-computer.sh [--transport stdio|http]
# HTTP requires CONTEXTBRIDGE_COMPUTER_TOKEN; stdio is for local MCP clients that launch this script.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m contextbridge.computer --config "${CONTEXTBRIDGE_COMPUTER_CONFIG:-$ROOT/configs/computer.yaml}" "$@"
