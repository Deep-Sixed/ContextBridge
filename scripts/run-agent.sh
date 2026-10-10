#!/usr/bin/env bash
# Usage: run-agent.sh                      connect and serve (after enrolling)
#        run-agent.sh enroll --code CODE   one-time registration with the gateway
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
CONFIG="${CONTEXTBRIDGE_AGENT_CONFIG:-$ROOT/configs/agent.yaml}"
if [[ "${1:-run}" == "enroll" ]]; then
  shift
  exec python3 -m contextbridge.remote.agent enroll --config "$CONFIG" "$@"
fi
exec python3 -m contextbridge.remote.agent run --config "$CONFIG"
