# ContextBridge

A read-only MCP gateway that gives AI agents authenticated access to approved JSONL project context.

**Security model:** exactly two operations (`search` and `fetch`), default-deny tool middleware, read-only annotations, audit logging, and a static bearer token (at least 32 characters) required at startup. Error details are masked from clients. Only allowlisted top-level record fields are served; the `metadata` object is served as-is. It binds only to the loopback interface by default.

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
| `UGA_MCP_SEARCH_LIMIT` | `10` | Maximum `search` results |
| `UGA_MCP_FETCH_MAX_CHARS` | `100000` | Maximum characters of `text` that `fetch` returns |
| `UGA_MCP_TOOL_TIMEOUT_SECONDS` | `10` | Timeout for a tool call |
| `UGA_MCP_METADATA_TIMEOUT_SECONDS` | `5` | Timeout for `initialize` and `tools/list` |

Where a setting has both an environment variable and a config key, the environment variable wins. An unset, unparsable, or non-positive value for the last four falls back to the default. A relative `serve.audit_log` is resolved against the working directory, not the config file's directory.

## Data format

Each JSONL line is one approved record with `id` (a non-empty string or integer), `title`, `text`, and `url`, plus an optional `metadata` object. `title`, `text`, and `url` must be present and not `null`; their values are served as strings, and so is an integer `id` (record `7` is fetched as `"7"`). Of the other top-level keys, only the approved fields listed in `_OPTIONAL_TOP_LEVEL_FIELDS` in `src/uga/adapter.py` are kept; any other key is dropped at load time and is never served or searched. The allowlist does not apply inside `metadata`, which is served and searched in full, so keep out of it anything clients must not see.

Blank lines are skipped. Invalid JSON, a missing required field, or a duplicate `id` stops startup.

## Tools

| Tool | Input | Returns |
| --- | --- | --- |
| `search` | `query` | `{"results": [...]}` with up to `UGA_MCP_SEARCH_LIMIT` hits. Each hit has `id`, `title`, and `url`, plus whichever of `summary`, `snippet`, `bank_id`, `record_kind`, `status`, and `updated_at` the record has (top-level field first, then `metadata`). |
| `fetch` | `id` | The full record: `id`, `title`, `text`, `url`, `metadata`, and the approved top-level fields it has. |

Search is a case-insensitive substring match against the values of `title`, `text`, `url`, `metadata`, and the approved fields; it does not match the `id` or JSON key names. An empty query returns the first records in file order. `fetch` of an unknown id fails with `Record not found: <id>`.

`fetch` returns at most `UGA_MCP_FETCH_MAX_CHARS` characters of a record's `text`. A longer text is cut to that length, and the response adds `truncated: true` and the full `text_length`. Other fields are returned as exported.

Both tools declare `readOnlyHint=true`, `destructiveHint=false`, `idempotentHint=true`, and `openWorldHint=false`. They only read the snapshot loaded at startup, so changes to the JSONL file take effect on restart. The server reports the package version (`uga.__version__`) in `serverInfo`, and its MCP `instructions` tell agents to search, then fetch by id, and to treat record text as data rather than instructions.

## Audit log

Each `initialize`, `tools/list`, and `tools/call` request, and each HTTP request rejected by auth, is written as one JSON line to stderr (prefixed with `[uga audit] `) and, if `UGA_AUDIT_LOG` (or `serve.audit_log` in the config) is set, to that file. Missing parent directories are created, and a new file gets mode `0600`. Other MCP requests, such as `ping`, and an authenticated `GET /` are not audited.

A permitted tool call produces two lines that share a `request_id`: one from the tool and one from the policy middleware. A call to any other tool produces one line with `detail: "policy_denied"`, and its arguments are not logged. Rejected HTTP requests are logged as `tool: "auth"` with `missing_token`, `invalid_token`, or `forbidden`.

`fetch` ids are logged as given. Queries are logged as their length and the first 16 hex digits of an unsalted SHA-256 hash, which links repeated queries but does not hide short or guessable ones. Set `UGA_AUDIT_LOG_QUERY_TEXT=1` to also log a preview of up to 80 characters.

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
| `start_search` | `path`, `pattern`, `search_type`, `file_pattern`, `ignore_case`, `literal`, `include_hidden`, `context_lines`, `max_results`, `timeout_ms` | Starts a recursive search in the background and returns a `search_id`, its status, and the first 100 results |
| `get_more_search_results` | `search_id`, `offset`, `length` | A page of results (up to 500); a negative `offset` counts from the end |
| `stop_search` | `search_id` | Stops a running search; the results found so far stay available |
| `list_searches` | none | Recent searches with their status and result counts |

Read tools, including the four search tools, are annotated read-only and are offered even when every root is read-only. `write_file`, `edit_block` and `delete_file` are marked destructive.

**Search:** `search_type` is `files` (the default) or `content`.

- A `files` search matches file and directory names. The pattern is a glob if it contains `*`, `?` or `[`, and a substring otherwise.
- A `content` search matches each line of a text file against a regular expression (Python `re` syntax), or against a plain string with `literal: true`. Results have the `path`, the 1-based `line` number and the line's `text`, plus `before` and `after` lists when `context_lines` (0–10) is set.
- `ignore_case` defaults to true. `file_pattern` limits which files are searched, for example `*.py` or `*.{ts,tsx}|*.md`, and is matched against file names case-insensitively. With `file_pattern` set, a `files` search reports only files, not directories.
- Hidden entries (names starting with `.`) are skipped unless `include_hidden` is true.

The search starts at `path` (a directory, or a single file for a `content` search) and walks every level below it. Symlinks are reported by a `files` search but never followed, and the trash is never searched. A `content` search skips binary files (a NUL byte in the first 8 KiB) and files over `max_search_file_bytes`, and reports the counts in `skipped`. Lines longer than 500 characters are cut, and a match on a cut line is marked `truncated`.

`start_search` waits up to one second, so a quick search returns complete. A longer one keeps running, and `get_more_search_results` returns its results so far, with `status: "running"` and `has_more: true` until it finishes. The final status is `completed`, `cancelled`, `timed_out` or `failed`; `limit_reached` is true when `max_results` (default 500, at most 5000) or the 8 MiB per-search cap stopped it early.

Each search runs in its own worker process (`src/uga/fs_search_worker.py`, started with `python -I`), so `stop_search` and `timeout_ms` (default 30000, at most 300000) stop it even inside a slow regular expression. On Linux and macOS the worker also sets an alarm a few seconds past its timeout, so it ends even if the server dies first. At most 4 searches run at once. The 10 most recent are kept in memory, and the oldest finished one is dropped to make room, so search ids are not kept across restarts. Searches are shared: every client with the route's token can list, page through and stop them.

**Deletion is recoverable:** each deleted item is kept under `.contextbridge-trash/<trash_id>/`, next to a `<trash_id>.json` file recording its original path. No tool can read, list, change or empty the trash; recover or purge items from the host.

**Limits:** `max_read_bytes` and `max_write_bytes` (1 MiB each by default) cap a response and a write, `max_list_entries` (1000) caps a listing, and `max_search_file_bytes` (10 MiB) is the largest file a content search reads. Calls use the same `UGA_MCP_TOOL_TIMEOUT_SECONDS` and `UGA_MCP_METADATA_TIMEOUT_SECONDS` settings as the gateway. Text must be UTF-8; binary files are refused.

**Audit:** lines go to stderr and to `CONTEXTBRIDGE_FS_AUDIT_LOG` (or `serve.audit_log`, resolved against the working directory) with `route: "fs"`. Paths are logged as the client sent them, with byte counts for reads and writes and the trash location for deletes. Refused paths are logged with `detail: "path_denied"`. Search lines carry the `search_id`, and those that return results also carry a `result_count`. Like the gateway's queries, a search pattern is logged only as its length and hash.

**Known limits:** checks run before each operation, so another local process that swaps a symlink in between can still redirect it; only the final component is opened with `O_NOFOLLOW`. Likewise, a destination created between `move_file`'s check and the rename is replaced. Hard links that already exist inside a root are not detected.

## Development

```sh
python3 -m pip install -e ".[test]"
python3 -m pytest
```

`tests/test_contract.py` pins the MCP contract clients see: the exact tool set, annotations, input schemas, reported version, server instructions, and policy denial. `tests/test_entrypoint.py` starts the real `python -m uga.gateway` entrypoint and checks bearer auth over HTTP. `tests/test_fs.py` covers the filesystem operations and path rules, `tests/test_fs_search.py` covers search matching and search sessions (including stopping and timing out a search stuck in a regular expression), and `tests/test_fs_gateway.py` pins the filesystem route's MCP contract and starts its entrypoint. CI runs the suite on Python 3.11 with the oldest supported fastmcp and on Python 3.13 with the newest 3.x release.

## Access model

This standalone gateway does not depend on Authentik. It does **not** include an OAuth proxy, public HTTPS listener, or ChatGPT/Claude Web OAuth discovery. To expose it to remote AI clients, use a separate authenticated TLS/OAuth access layer. Do not set `serve.host` to a public interface or directly forward port 8790 (or the filesystem route's 8791) to the internet.

## Documentation

The PDFs in `docs/` are planning documents. The filesystem route implements the roadmap's filesystem operations and its file and content search (but not searching inside Excel files); nothing else in it (terminal, processes, documents, remote devices, synchronization) is implemented, and the read-only gateway's default-deny policy rejects such tools. The documents refer to two target machines, Friday (Linux) and Thanatos (Windows).

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
