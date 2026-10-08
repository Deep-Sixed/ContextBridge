#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${CONTEXTBRIDGE_FS_AUTH_TOKEN:?Set CONTEXTBRIDGE_FS_AUTH_TOKEN using a secret manager}"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m uga.fs_gateway --config "${CONTEXTBRIDGE_FS_CONFIG:-$ROOT/configs/contextbridge-fs.yaml}"
