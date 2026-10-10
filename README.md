# ContextBridge

A read-only MCP gateway that gives AI agents authenticated access to approved JSONL project context.

**Security model:** exactly two operations (`search` and `fetch`), default-deny policy for tools and every other MCP method, read-only annotations, audit logging, and a static bearer token (at least 32 characters) required at startup. Error details are masked from clients. Only allowlisted record fields are served, at the top level and inside `metadata`. It binds only to the loopback interface by default.

A separate [filesystem route](#filesystem-route) serves file tools from configured directories. It runs as its own server with its own token, so the read-only gateway's tool surface is unchanged.

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

MCP clients connect over streamable HTTP to `http://127.0.0.1:8790/mcp` (the `serve.host` and `serve.port` from the config) and send `Authorization: Bearer <MCP_AUTH_TOKEN>`.

Every HTTP route requires the token, including `GET /`, which returns the service name, the MCP path, and the tool names. A request without a valid token gets `401` and is audited as `auth`. The filesystem route applies the same rule with its own token.

## Configuration

| Setting | Default | Purpose |
| --- | --- | --- |
| `MCP_AUTH_TOKEN` | required | Bearer token clients must send; at least 32 characters |
| `UGA_DATACORE_JSONL` or `datacore_jsonl` | one is required | JSONL export to serve |
| `serve.host` | `127.0.0.1` | Listen address |
| `serve.port` | required | Listen port (`8790` in `configs/contextbridge.yaml`) |
| `name` | `Nexus UGA` | Server name reported in `serverInfo` and by `GET /` |
| `UGA_AUDIT_LOG` or `serve.audit_log` | unset | Audit log file (see [Audit log](#audit-log)) |
| `UGA_AUDIT_LOG_QUERY_TEXT` | off | `1`, `true`, or `yes` also logs a query preview |
| `UGA_AUDIT_HASH_KEY` | random per run | Key for the audit log's query hash |
| `serve.forwarded_allow_ips` | unset | Proxy addresses whose `X-Forwarded-For` is trusted for the audited `peer` |
| `UGA_MCP_SEARCH_LIMIT` | `10` | Maximum `search` results |
| `UGA_MCP_FETCH_MAX_CHARS` | `100000` | Maximum characters of `text` that `fetch` returns |
| `UGA_MCP_TOOL_TIMEOUT_SECONDS` | `10` | Timeout for a tool call |
| `UGA_MCP_METADATA_TIMEOUT_SECONDS` | `5` | Timeout for `initialize` and `tools/list` |

Where a setting has both an environment variable and a config key, the environment variable wins. An unset, unparsable, or non-positive value for the last four falls back to the default. A relative `serve.audit_log` is resolved against the config file's directory.

## Data format

Each JSONL line is one approved record with `id` (a non-empty string or integer) and the strings `title`, `text`, and `url`, plus an optional `metadata` object. An integer `id` is served as a string (record `7` is fetched as `"7"`). Other keys, at the top level or inside `metadata`, are kept only if they are approved fields listed in `_APPROVED_FIELDS` in `src/uga/adapter.py`; any other key is dropped at load time and is never served or searched. An approved field keeps its whole value, including nested objects.

Blank lines are skipped. Invalid JSON, a missing or non-string `title`, `text`, or `url`, or a duplicate `id` stops startup.

## Tools

| Tool | Input | Returns |
| --- | --- | --- |
| `search` | `query` | `{"results": [...]}` with up to `UGA_MCP_SEARCH_LIMIT` hits. Each hit has `id`, `title`, and `url`, plus whichever of `summary`, `snippet`, `bank_id`, `record_kind`, `status`, and `updated_at` the record has (top-level field first, then `metadata`). |
| `fetch` | `id` | The full record: `id`, `title`, `text`, `url`, `metadata`, and the approved top-level fields it has. |

Search is a case-insensitive substring match against the values of `title`, `text`, `url`, `metadata`, and the approved fields; it does not match the `id` or JSON key names, and never matches across two fields. An empty query returns the first records in file order. `fetch` of an unknown id fails with `Record not found: <id>`.

`fetch` returns at most `UGA_MCP_FETCH_MAX_CHARS` characters of a record's `text`. A longer text is cut to that length, and the response adds `truncated: true` and the full `text_length`. Other fields are returned as exported.

Both tools declare `readOnlyHint=true`, `destructiveHint=false`, `idempotentHint=true`, and `openWorldHint=false`. They only read the snapshot loaded at startup, so changes to the JSONL file take effect on restart. The server reports the package version (`uga.__version__`) in `serverInfo`, and its MCP `instructions` tell agents to search, then fetch by id, and to treat record text as data rather than instructions.

Other MCP methods follow the same default-deny policy: `resources/list`, `resources/templates/list` and `prompts/list` return empty lists, `ping` is answered, and every other request (for example `resources/read`, `prompts/get`, `logging/setLevel`) is rejected.

## Audit log

Each MCP request except `ping`, and each HTTP request rejected by auth, is written as one JSON line to stderr (prefixed with `[uga audit] `) and, if `UGA_AUDIT_LOG` (or `serve.audit_log` in the config, resolved against the config file's directory) is set, to that file. Missing parent directories are created. The file is opened without following symlinks, must be a regular file, and is set to mode `0600`, including when it already exists. An authenticated `GET /` is not audited.

Each line has a `request_id` that is unique per request, and a tool call's line carries what the tool recorded (`record_id`, `result_count`, the query hash). Denied tools and methods are logged with `detail: "policy_denied"`, and their arguments are not logged. Requests rejected by bearer auth are logged as `tool: "auth"` with `missing_token`, `invalid_token`, or `forbidden`. Methods the MCP SDK does not implement at all are rejected by the SDK and not logged. Client-supplied strings such as tool names and record ids are cut to 200 characters.

Queries are recorded as their length and a keyed hash (the first 16 hex digits of an HMAC-SHA256); set `UGA_AUDIT_LOG_QUERY_TEXT=1` to also log a preview of up to 80 characters. Set `UGA_AUDIT_HASH_KEY` to a random secret to make the hash of the same query stable across restarts; without it a random key is used for each run, and the hash cannot be reversed by hashing guesses without the key.

The `peer` field is the address of the TCP connection. `X-Forwarded-For` is ignored unless the proxy's address is listed in `serve.forwarded_allow_ips`. If you serve `create_uga_server().http_app()` with your own uvicorn, pass `proxy_headers=False` (uvicorn trusts the header from 127.0.0.1 by default).

## Filesystem route

`python -m uga.fs_gateway` (or `./scripts/run-contextbridge-fs.sh`) is a second MCP server on port 8791. It gives agents file access inside the directories listed under `filesystem.roots` in `configs/contextbridge-fs.yaml`. The shipped config lists none, so the route refuses to start until you add some.

```sh
export CONTEXTBRIDGE_FS_AUTH_TOKEN="<a different strong secret>"
./scripts/run-contextbridge-fs.sh
```

`CONTEXTBRIDGE_FS_AUTH_TOKEN` follows the same rules as `MCP_AUTH_TOKEN` and must differ from it; the route checks this when both are set in its environment. Set `CONTEXTBRIDGE_FS_CONFIG` to use another config file. The config takes the same `name` (default `ContextBridge Files`) and `serve` keys as the gateway's, plus the `filesystem` section.

**Path rules:** every path must be absolute or start with `~` (the server user's home directory). It is resolved with symlinks followed and must land inside a root, so `..` and symlinks cannot reach outside. Roots are read-only unless they set `writable: true`, must exist, and must not overlap. The server's MCP `instructions` list each root and whether it is writable. Write tools are only advertised when at least one root is writable, and calls to any tool outside the advertised set are denied and audited.

| Tool | Input | Notes |
| --- | --- | --- |
| `read_file` | `path`, `offset`, `length` | UTF-8 text by line; a negative `offset` reads the last lines; `length` defaults to 1000 |
| `read_multiple_files` | `paths` | Up to 50 files; one file's error does not fail the rest |
| `list_directory` | `path`, `depth` | `depth` 1–10, default 2; symlinks are listed, not followed |
| `get_file_info` | `path` | Size, timestamps, permissions, type, whether it is a symlink |
| `write_file` | `path`, `content`, `mode` | `rewrite` (replaces an existing file atomically, keeping its permissions) or `append`; the parent must exist |
| `edit_block` | `file_path`, `old_string`, `new_string`, `expected_replacements` | Exact text; fails unless the match count equals `expected_replacements` (default 1) |
| `create_directory` | `path` | Creates missing parents |
| `move_file` | `source`, `destination` | Moves or renames; refuses a destination that already exists |
| `delete_file` | `path`, `recursive` | Moves the item to `<root>/.contextbridge-trash/`; a non-empty directory needs `recursive` |

Read tools are annotated read-only. `write_file`, `edit_block` and `delete_file` are marked destructive.

**Deletion is recoverable:** each deleted item is kept under `.contextbridge-trash/<trash_id>/`, next to a `<trash_id>.json` file recording its original path. No tool can read, list, change or empty the trash; recover or purge items from the host.

**Limits:** `max_read_bytes` and `max_write_bytes` (1 MiB each by default) cap a response and a write, and `max_list_entries` (1000) caps a listing. Calls use the same `UGA_MCP_TOOL_TIMEOUT_SECONDS` and `UGA_MCP_METADATA_TIMEOUT_SECONDS` settings as the gateway. Text must be UTF-8; binary files are refused.

**Audit:** lines go to stderr and to `CONTEXTBRIDGE_FS_AUDIT_LOG` (or `serve.audit_log`, resolved against the config file's directory) with `route: "fs"`. As on the gateway, each request is one line, and `X-Forwarded-For` is ignored unless `serve.forwarded_allow_ips` lists the proxy. Paths are logged as the client sent them, with byte counts for reads and writes and the trash location for deletes. Refused paths are logged with `detail: "path_denied"`.

**Known limits:** checks run before each operation, so another local process that swaps a symlink in between can still redirect it; only the final component is opened with `O_NOFOLLOW`. Likewise, a destination created between `move_file`'s check and the rename is replaced. Hard links that already exist inside a root are not detected.

## Development

```sh
python3 -m pip install -e ".[test]"
python3 -m pytest
```

`tests/test_contract.py` pins the MCP contract clients see: the exact tool set, annotations, input schemas, reported version, server instructions, and policy denial. `tests/test_entrypoint.py` starts the real `python -m uga.gateway` entrypoint and checks bearer auth over HTTP. `tests/test_fs.py` covers the filesystem operations and path rules, and `tests/test_fs_gateway.py` pins the filesystem route's MCP contract and starts its entrypoint. CI runs the suite on Python 3.11 with the oldest supported fastmcp and on Python 3.13 with the newest 3.x release.

## Access model

This standalone gateway does not depend on Authentik. It does **not** include an OAuth proxy, public HTTPS listener, or ChatGPT/Claude Web OAuth discovery. To expose it to remote AI clients, use a separate authenticated TLS/OAuth access layer. Do not set `serve.host` to a public interface or directly forward port 8790 (or the filesystem route's 8791) to the internet.

## Documentation

The PDFs in `docs/` are planning documents. The filesystem route implements the roadmap's filesystem operations; nothing else in it (search across files, terminal, processes, documents, remote devices, synchronization) is implemented, and the read-only gateway's default-deny policy rejects such tools. The documents refer to two target machines, Friday (Linux) and Thanatos (Windows).

- `docs/capability-roadmap.pdf` lists the capabilities ContextBridge targets, with an implementation checklist. The checklist is a blank tracker, not a status report. It is generated by `scripts/build-roadmap-pdf.py`.
- `docs/computer-use-linux-review.pdf` evaluates `agent-sh/computer-use-linux` as a Linux desktop-control engine for ContextBridge. It is generated by `scripts/build-review-pdf.py`.

Both scripts share `scripts/pdf_common.py`. To rebuild a PDF after editing its script (requires the DejaVu fonts; set `CONTEXTBRIDGE_FONT_DIR` if they are not in a standard font directory):

```sh
python3 -m pip install -e '.[docs]'
./scripts/build-roadmap-pdf.py
./scripts/build-review-pdf.py
```

## Status

Standalone extraction from an archived UGA (Unidirectional Gateway Appliance) implementation. That is why the package is `uga`, environment variables start with `UGA_`, the gateway's default name is `Nexus UGA`, and its timeout errors say "Nexus Datacore". Authentication-front/sidecar deployments and systemd services intentionally excluded. The code is not yet production-validated.
