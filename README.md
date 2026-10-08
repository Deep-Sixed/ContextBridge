# ContextBridge

A read-only MCP gateway that gives AI agents authenticated access to approved JSONL project context.

**Security model:** exactly two operations (`search` and `fetch`), default-deny tool middleware, read-only annotations, audit logging, and a static bearer token (at least 32 characters) required at startup. Error details are masked from clients, and only allowlisted record fields are served. It binds only to the loopback interface by default.

## Installation

```sh
python3 -m pip install -e .
export MCP_AUTH_TOKEN="<strong random secret provided by secret manager>"
export UGA_DATACORE_JSONL="/path/to/approved/datacore.fetch.v1.jsonl"
./scripts/run-contextbridge.sh
```

Requires fastmcp 3.x. `MCP_AUTH_TOKEN` must be at least 32 characters (for example `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`).

The data export is required: set `UGA_DATACORE_JSONL`, or `datacore_jsonl` in the config file (a relative path is resolved against the config file's directory). The environment variable wins. The export is loaded and validated at startup, and the gateway refuses to start if it is missing or invalid.

## Data format

Each JSONL line is one approved record with `id` (a non-empty string or integer), `title`, `text`, and `url`, plus an optional `metadata` object. Of the other top-level keys, only the approved fields listed in `_OPTIONAL_TOP_LEVEL_FIELDS` in `src/uga/adapter.py` are kept; any other key is dropped at load time and is never served or searched. Search matches field values, not JSON key names.

## Audit log

Every request is written as one JSON line to stderr and, if `UGA_AUDIT_LOG` (or `serve.audit_log` in the config) is set, to that file, which is created with mode `0600`. A tool call produces two lines (one from the policy middleware, one from the tool) that share a `request_id`. Rejected HTTP requests are logged as `tool: "auth"` with `missing_token` or `invalid_token`. Queries are recorded as a hash and length only; set `UGA_AUDIT_LOG_QUERY_TEXT=1` to also log the first 80 characters.

## Access model

This standalone gateway does not depend on Authentik. It does **not** include an OAuth proxy, public HTTPS listener, or ChatGPT/Claude Web OAuth discovery. To expose it to remote AI clients, use a separate authenticated TLS/OAuth access layer. Do not directly forward port 8790 to the internet.

## Status

Standalone extraction from an archived UGA implementation. Authentication-front/sidecar deployments and systemd services intentionally excluded. The code is not yet production-validated.
