# ContextBridge

A read-only MCP gateway that gives AI agents authenticated access to approved JSONL project context.

**Security model:** exactly two operations (`search` and `fetch`), default-deny tool middleware, read-only annotations, audit logging, and a static bearer token (at least 32 characters) required at startup. Error details are masked from clients. Only allowlisted top-level record fields are served; the `metadata` object is served as-is. It binds only to the loopback interface by default.

## Installation

```sh
python3 -m pip install -e .
export MCP_AUTH_TOKEN="<strong random secret provided by secret manager>"
export UGA_DATACORE_JSONL="/path/to/approved/datacore.fetch.v1.jsonl"
./scripts/run-contextbridge.sh
```

Requires Python 3.11+ and fastmcp 3.x. `MCP_AUTH_TOKEN` must be at least 32 characters (for example `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`).

The data export is required: set `UGA_DATACORE_JSONL`, or `datacore_jsonl` in the config file (a relative path is resolved against the config file's directory). The environment variable wins. The export is loaded and validated at startup, and the gateway refuses to start if it is missing or invalid.

`scripts/run-contextbridge.sh` always uses `configs/contextbridge.yaml`. To use another config file, run `python3 -m uga.gateway --config <path>`.

## Connecting

MCP clients connect over streamable HTTP to `http://127.0.0.1:8790/mcp` (the `serve.host` and `serve.port` from the config) and send `Authorization: Bearer <MCP_AUTH_TOKEN>`. Requests without a valid token get `401`.

`GET /` is not authenticated. It returns the service name, the MCP path, and the tool names, and can be used as a health check.

## Configuration

| Setting | Default | Purpose |
| --- | --- | --- |
| `MCP_AUTH_TOKEN` | required | Bearer token clients must send; at least 32 characters |
| `UGA_DATACORE_JSONL` or `datacore_jsonl` | one is required | JSONL export to serve |
| `serve.host` | `127.0.0.1` | Listen address |
| `serve.port` | required | Listen port (`8790` in `configs/contextbridge.yaml`) |
| `name` | `Nexus UGA` | Server name reported in `serverInfo` |
| `UGA_AUDIT_LOG` or `serve.audit_log` | unset | Audit log file (see [Audit log](#audit-log)) |
| `UGA_AUDIT_LOG_QUERY_TEXT` | off | `1`, `true`, or `yes` also logs a query preview |
| `UGA_MCP_SEARCH_LIMIT` | `10` | Maximum `search` results |
| `UGA_MCP_TOOL_TIMEOUT_SECONDS` | `10` | Timeout for a tool call |
| `UGA_MCP_METADATA_TIMEOUT_SECONDS` | `5` | Timeout for `initialize` and `tools/list` |

Where a setting has both an environment variable and a config key, the environment variable wins. An unset, unparsable, or non-positive value for the last three falls back to the default. A relative `serve.audit_log` is resolved against the working directory, not the config file's directory.

## Data format

Each JSONL line is one approved record with `id` (a non-empty string or integer), `title`, `text`, and `url`, plus an optional `metadata` object. `title`, `text`, and `url` must be present and not `null`; their values are served as strings, and so is an integer `id` (record `7` is fetched as `"7"`). Of the other top-level keys, only the approved fields listed in `_OPTIONAL_TOP_LEVEL_FIELDS` in `src/uga/adapter.py` are kept; any other key is dropped at load time and is never served or searched. The allowlist does not apply inside `metadata`, which is served and searched in full, so keep out of it anything clients must not see.

Blank lines are skipped. Invalid JSON, a missing required field, or a duplicate `id` stops startup.

## Tools

| Tool | Input | Returns |
| --- | --- | --- |
| `search` | `query` | `{"results": [...]}` with up to `UGA_MCP_SEARCH_LIMIT` hits. Each hit has `id`, `title`, and `url`, plus whichever of `summary`, `snippet`, `bank_id`, `record_kind`, `status`, and `updated_at` the record has (top-level field first, then `metadata`). |
| `fetch` | `id` | The full record: `id`, `title`, `text`, `url`, `metadata`, and the approved top-level fields it has. |

Search is a case-insensitive substring match against the values of `title`, `text`, `url`, `metadata`, and the approved fields; it does not match the `id` or JSON key names. An empty query returns the first records in file order. `fetch` of an unknown id fails with `Record not found: <id>`.

Both tools declare `readOnlyHint=true`, `destructiveHint=false`, `idempotentHint=true`, and `openWorldHint=false`. They only read the snapshot loaded at startup, so changes to the JSONL file take effect on restart. The server reports the package version (`uga.__version__`) in `serverInfo`.

## Audit log

Each `initialize`, `tools/list`, and `tools/call` request, and each HTTP request rejected by auth, is written as one JSON line to stderr (prefixed with `[uga audit] `) and, if `UGA_AUDIT_LOG` (or `serve.audit_log` in the config) is set, to that file. Missing parent directories are created, and a new file gets mode `0600`. Other MCP requests, such as `ping`, and `GET /` are not audited.

A permitted tool call produces two lines that share a `request_id`: one from the tool and one from the policy middleware. A call to any other tool produces one line with `detail: "policy_denied"`, and its arguments are not logged. Rejected HTTP requests are logged as `tool: "auth"` with `missing_token`, `invalid_token`, or `forbidden`.

`fetch` ids are logged as given. Queries are logged as their length and the first 16 hex digits of an unsalted SHA-256 hash, which links repeated queries but does not hide short or guessable ones. Set `UGA_AUDIT_LOG_QUERY_TEXT=1` to also log a preview of up to 80 characters.

## Development

```sh
python3 -m pip install -e ".[test]"
python3 -m pytest
```

`tests/test_contract.py` pins the MCP contract clients see: the exact tool set, annotations, input schemas, reported version, and policy denial. `tests/test_entrypoint.py` starts the real `python -m uga.gateway` entrypoint and checks bearer auth over HTTP. CI runs the suite on Python 3.11 with the oldest supported fastmcp and on Python 3.13 with the newest 3.x release.

## Access model

This standalone gateway does not depend on Authentik. It does **not** include an OAuth proxy, public HTTPS listener, or ChatGPT/Claude Web OAuth discovery. To expose it to remote AI clients, use a separate authenticated TLS/OAuth access layer. Do not set `serve.host` to a public interface or directly forward port 8790 to the internet.

## Documentation

The PDFs in `docs/` are planning documents for a broader ContextBridge (filesystem, terminal, remote devices, synchronization). None of that is implemented here, and this gateway's default-deny policy rejects such tools. The documents refer to two target machines, Friday (Linux) and Thanatos (Windows).

- `docs/desktop-commander-inventory.pdf` lists the Desktop Commander functionality ContextBridge targets, with an implementation checklist. It is generated by `scripts/build-inventory-pdf.py`.
- `docs/computer-use-linux-review.pdf` evaluates `agent-sh/computer-use-linux` as a Linux desktop-control engine for ContextBridge. It has no generator script in this repository.

To rebuild the inventory PDF after editing the script (requires the DejaVu fonts; set `CONTEXTBRIDGE_FONT_DIR` if they are not in a standard font directory):

```sh
python3 -m pip install -e '.[docs]'
./scripts/build-inventory-pdf.py
```

## Status

Standalone extraction from an archived UGA (Unidirectional Gateway Appliance) implementation, which is why the package is `uga`, environment variables start with `UGA_`, and some server strings still say "Nexus UGA" or "Nexus Datacore". Authentication-front/sidecar deployments and systemd services intentionally excluded. The code is not yet production-validated.
