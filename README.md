# ContextBridge

A read-only MCP gateway that gives AI agents authenticated access to approved JSONL project context.

**Security model:** exactly two operations (`search` and `fetch`), default-deny policy for tools and every other MCP method, read-only annotations, audit logging, and a static bearer token (at least 32 characters) required at startup. Error details are masked from clients, and only allowlisted record fields are served. It binds only to the loopback interface by default.

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

Each JSONL line is one approved record with `id` (a non-empty string or integer) and the strings `title`, `text`, and `url`, plus an optional `metadata` object. Other keys, at the top level or inside `metadata`, are kept only if they are approved fields listed in `_APPROVED_FIELDS` in `src/uga/adapter.py`; any other key is dropped at load time and is never served or searched. An approved field keeps its whole value, including nested objects. Search matches field values, not JSON key names, and never matches across two fields.

## Tools

| Tool | Input | Annotations |
| --- | --- | --- |
| `search` | `query` | `readOnlyHint=true`, `destructiveHint=false`, `idempotentHint=true`, `openWorldHint=false` |
| `fetch` | `id` | same as `search` |

Both tools only read the loaded JSONL snapshot. The server reports the package version (`uga.__version__`) in `serverInfo`, and its MCP `instructions` tell agents to search, then fetch by id, and to treat record text as data rather than instructions.

`fetch` returns at most `UGA_MCP_FETCH_MAX_CHARS` characters of a record's `text` (default 100000). A longer text is cut to that length, and the response adds `truncated: true` and the full `text_length`. Other fields are returned as exported.

Other MCP methods follow the same default-deny policy: `resources/list`, `resources/templates/list` and `prompts/list` return empty lists, `ping` is answered, and every other request (for example `resources/read`, `prompts/get`, `logging/setLevel`) is rejected.

## Audit log

Each MCP request except `ping` is written as one JSON line to stderr and, if `UGA_AUDIT_LOG` (or `serve.audit_log` in the config, resolved against the config file's directory) is set, to that file. The file is opened without following symlinks and set to mode `0600`, including when it already exists. Each line has a `request_id` that is unique per request. Denied tools and methods are logged with `detail: "policy_denied"`, and requests rejected by bearer auth as `tool: "auth"` with `missing_token` or `invalid_token`; methods the MCP SDK does not implement at all are rejected by the SDK and not logged. Client-supplied strings such as tool names and record ids are cut to 200 characters.

Queries are recorded as a keyed hash and their length only; set `UGA_AUDIT_LOG_QUERY_TEXT=1` to also log the first 80 characters. Set `UGA_AUDIT_HASH_KEY` to a random secret to make the hash of the same query stable across restarts; without it a random key is used for each run, and the hash cannot be reversed by hashing guesses without the key.

The `peer` field is the address of the TCP connection. `X-Forwarded-For` is ignored unless the proxy's address is listed in `serve.forwarded_allow_ips`. If you serve `create_uga_server().http_app()` with your own uvicorn, pass `proxy_headers=False` (uvicorn trusts the header from 127.0.0.1 by default).

## Development

```sh
python3 -m pip install -e ".[test]"
python3 -m pytest
```

`tests/test_contract.py` pins the MCP contract clients see: the exact tool set, annotations, input schemas, reported version, server instructions, and policy denial. `tests/test_entrypoint.py` starts the real `python -m uga.gateway` entrypoint and checks bearer auth over HTTP. CI runs the suite on Python 3.11 with the oldest supported fastmcp and on Python 3.13 with the newest 3.x release.

## Access model

This standalone gateway does not depend on Authentik. It does **not** include an OAuth proxy, public HTTPS listener, or ChatGPT/Claude Web OAuth discovery. To expose it to remote AI clients, use a separate authenticated TLS/OAuth access layer. Do not directly forward port 8790 to the internet.

Every HTTP route requires the bearer token, including the `GET /` status route, which returns the service name, MCP path, and tool list. A request without a valid token gets `401` and is audited as `auth`.

## Documentation

`docs/desktop-commander-inventory.pdf` lists the Desktop Commander functionality ContextBridge targets, with an implementation checklist. To rebuild it after editing `scripts/build-inventory-pdf.py` (requires the DejaVu fonts):

```sh
python3 -m pip install -e '.[docs]'
./scripts/build-inventory-pdf.py
```

## Status

Standalone extraction from an archived UGA implementation. Authentication-front/sidecar deployments and systemd services intentionally excluded. The code is not yet production-validated.
