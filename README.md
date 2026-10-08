# ContextBridge

A read-only MCP gateway that gives AI agents authenticated access to approved JSONL project context.

**Security model:** exactly two operations (`search` and `fetch`), default-deny tool middleware, read-only annotations, audit logging, and a static bearer token required at startup. It binds only to the loopback interface by default.

## Installation

```sh
python3 -m pip install -e .
export MCP_AUTH_TOKEN="<strong random secret provided by secret manager>"
export UGA_DATACORE_JSONL="/path/to/approved/datacore.fetch.v1.jsonl"
./scripts/run-contextbridge.sh
```

The JSONL export must contain approved records with `id`, `title`, `text`, and `url` fields.

## Access model

This standalone gateway does not depend on Authentik. It does **not** include an OAuth proxy, public HTTPS listener, or ChatGPT/Claude Web OAuth discovery. To expose it to remote AI clients, use a separate authenticated TLS/OAuth access layer. Do not directly forward port 8790 to the internet.

## Status

Standalone extraction from an archived UGA implementation. Authentication-front/sidecar deployments and systemd services intentionally excluded. The code is not yet production-validated.
