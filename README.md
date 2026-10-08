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

## Tools

| Tool | Input | Annotations |
| --- | --- | --- |
| `search` | `query` | `readOnlyHint=true`, `destructiveHint=false`, `idempotentHint=true`, `openWorldHint=false` |
| `fetch` | `id` | same as `search` |

Both tools only read the loaded JSONL snapshot. The server reports the package version (`uga.__version__`) in `serverInfo`.

## Audit log

Every MCP request (`initialize`, `tools/list`, `tools/call`) writes one JSON line to stderr, and to `UGA_AUDIT_LOG` (or `serve.audit_log` in the config) when set. Each line carries `request_id` (the JSON-RPC id), `client` (the client's self-reported `clientInfo`, unauthenticated), `success`, `elapsed_ms`, and a `detail` on failure such as `policy_denied`, `not_found`, or `timeout`. Tool calls add `query_hash` or `record_id` and `result_count`. Arguments to denied tools are never logged.

Query text is not logged by default. Set `UGA_AUDIT_QUERY_PREVIEW=1` to add the first 80 characters as `query_preview`.

## Development

```sh
python3 -m pip install -e ".[test]"
python3 -m pytest
```

The tests pin the MCP contract: the exact tool set, annotations, input schemas, reported version, policy denial, audit lines, and that `/mcp` rejects requests without the bearer token. CI runs them on Python 3.11 with the oldest supported fastmcp (3.0.0) and on Python 3.13 with the newest 3.x release.

## Access model

This standalone gateway does not depend on Authentik. It does **not** include an OAuth proxy, public HTTPS listener, or ChatGPT/Claude Web OAuth discovery. To expose it to remote AI clients, use a separate authenticated TLS/OAuth access layer. Do not directly forward port 8790 to the internet.

## Status

Standalone extraction from an archived UGA implementation. Authentication-front/sidecar deployments and systemd services intentionally excluded. The code is not yet production-validated.
