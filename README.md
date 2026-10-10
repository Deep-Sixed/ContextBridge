# ContextBridge

A self-hosted MCP gateway that gives AI assistants authenticated, policy-controlled access to approved knowledge and to your own computers. ContextBridge has no runtime dependency on any hosted relay: its own gateway, agents, and transport do the work.

It has three routes, each with its own server, port, and credential:

| Route | Module | Tools | Credential |
|---|---|---|---|
| Knowledge (UGA) | `uga.gateway` | `search`, `fetch` over approved JSONL records | `MCP_AUTH_TOKEN` |
| Filesystem | `uga.fs_gateway` | file tools inside configured directories (see [Filesystem route](#filesystem-route)) | `CONTEXTBRIDGE_FS_AUTH_TOKEN` |
| Computer | `contextbridge.computer` | files, commands, sessions, processes | `CONTEXTBRIDGE_COMPUTER_TOKEN` |

Being able to read knowledge never grants file or computer access. Each route accepts only its own token. The filesystem and computer routes each refuse to start if their token matches either other route's token, when both are set in their environment.

The computer route can also serve ChatGPT, Claude, and other remote MCP clients through a second, OAuth-protected endpoint. Each client gets only the permissions and devices you approve for it (see [Remote MCP clients](#remote-mcp-clients-chatgpt-claude)).

## Installation

```sh
python3 -m pip install -e '.[test]'
python3 -m pytest        # includes acceptance tests that launch the gateways and an agent as real processes
```

ContextBridge requires Python 3.11+ and FastMCP 3.x (`fastmcp>=3,<4`). It has no runtime dependency on Node or npx, and the acceptance tests run both gateways in an environment without them.

`tests/test_contract.py` pins the knowledge route's MCP contract: the exact tool set, annotations, input schemas, reported version, server instructions, and policy denial. `tests/test_entrypoint.py` starts the real `python -m uga.gateway` entrypoint and checks bearer auth over HTTP. `tests/test_fs.py` covers the filesystem operations and path rules, and `tests/test_fs_gateway.py` pins the filesystem route's MCP contract and starts its entrypoint. CI runs the whole suite on Ubuntu and Windows, with Python 3.11 against the oldest supported FastMCP (3.0.0) and Python 3.13 against the newest 3.x release.

## Knowledge route

**Security model:** exactly two operations (`search` and `fetch`), default-deny policy for tools and every other MCP method, read-only annotations, audit logging, and a static bearer token (at least 32 characters) required at startup. Error details are masked from clients. Only allowlisted record fields are served, at the top level and inside `metadata`. It binds only to the loopback interface by default.

```sh
export MCP_AUTH_TOKEN="<strong random secret provided by secret manager>"
export UGA_DATACORE_JSONL="/path/to/approved/datacore.fetch.v1.jsonl"
./scripts/run-contextbridge.sh
```

`MCP_AUTH_TOKEN` must be at least 32 characters (for example `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`).

The data export is required: set `UGA_DATACORE_JSONL`, or `datacore_jsonl` in the config file (a relative path is resolved against the config file's directory). The environment variable wins. The export is loaded and validated at startup, and the gateway refuses to start if it is missing or invalid.

`scripts/run-contextbridge.sh` always uses `configs/contextbridge.yaml`. To use another config file, run `python3 -m uga.gateway --config <path>`.

### Connecting

MCP clients connect over streamable HTTP to `http://127.0.0.1:8790/mcp` (the `serve.host` and `serve.port` from the config) and send `Authorization: Bearer <MCP_AUTH_TOKEN>`.

Every HTTP route requires the token, including `GET /`, which returns the service name, the MCP path, and the tool names. A request without a valid token gets `401` and is audited as `auth`. The filesystem route applies the same rule with its own token.

### Configuration

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

### Data format

Each JSONL line is one approved record with `id` (a non-empty string or integer) and the strings `title`, `text`, and `url`, plus an optional `metadata` object. An integer `id` is served as a string (record `7` is fetched as `"7"`). Other keys, at the top level or inside `metadata`, are kept only if they are approved fields listed in `_APPROVED_FIELDS` in `src/uga/adapter.py`; any other key is dropped at load time and is never served or searched. An approved field keeps its whole value, including nested objects.

Blank lines are skipped. Invalid JSON, a missing or non-string `title`, `text`, or `url`, or a duplicate `id` stops startup.

### Tools

| Tool | Input | Returns |
| --- | --- | --- |
| `search` | `query` | `{"results": [...]}` with up to `UGA_MCP_SEARCH_LIMIT` hits. Each hit has `id`, `title`, and `url`, plus whichever of `summary`, `snippet`, `bank_id`, `record_kind`, `status`, and `updated_at` the record has (top-level field first, then `metadata`). |
| `fetch` | `id` | The full record: `id`, `title`, `text`, `url`, `metadata`, and the approved top-level fields it has. |

Search is a case-insensitive substring match against the values of `title`, `text`, `url`, `metadata`, and the approved fields; it does not match the `id` or JSON key names, and never matches across two fields. An empty query returns the first records in file order. `fetch` of an unknown id fails with `Record not found: <id>`.

`fetch` returns at most `UGA_MCP_FETCH_MAX_CHARS` characters of a record's `text`. A longer text is cut to that length, and the response adds `truncated: true` and the full `text_length`. Other fields are returned as exported.

Both tools declare `readOnlyHint=true`, `destructiveHint=false`, `idempotentHint=true`, and `openWorldHint=false`. They only read the snapshot loaded at startup, so changes to the JSONL file take effect on restart. The server reports the package version (`uga.__version__`) in `serverInfo`, and its MCP `instructions` tell agents to search, then fetch by id, and to treat record text as data rather than instructions.

Other MCP methods follow the same default-deny policy: `resources/list`, `resources/templates/list` and `prompts/list` return empty lists, `ping` is answered, and every other request (for example `resources/read`, `prompts/get`, `logging/setLevel`) is rejected.

### Audit log

Each MCP request except `ping`, and each HTTP request rejected by auth, is written as one JSON line to stderr (prefixed with `[uga audit] `) and, if `UGA_AUDIT_LOG` (or `serve.audit_log` in the config, resolved against the config file's directory) is set, to that file. Missing parent directories are created. The file is opened without following symlinks, must be a regular file, and is set to mode `0600`, including when it already exists. An authenticated `GET /` is not audited.

Each line has a `request_id` that is unique per request, and a tool call's line carries what the tool recorded (`record_id`, `result_count`, the query hash). Denied tools and methods are logged with `detail: "policy_denied"`, and their arguments are not logged. Requests rejected by bearer auth are logged as `tool: "auth"` with `missing_token`, `invalid_token`, or `forbidden`. Methods the MCP SDK does not implement at all are rejected by the SDK and not logged. Client-supplied strings such as tool names and record ids are cut to 200 characters.

Queries are recorded as their length and a keyed hash (the first 16 hex digits of an HMAC-SHA256); set `UGA_AUDIT_LOG_QUERY_TEXT=1` to also log a preview of up to 80 characters. Set `UGA_AUDIT_HASH_KEY` to a random secret to make the hash of the same query stable across restarts; without it a random key is used for each run, and the hash cannot be reversed by hashing guesses without the key.

The `peer` field is the address of the TCP connection. `X-Forwarded-For` is ignored unless the proxy's address is listed in `serve.forwarded_allow_ips`. If you serve `create_uga_server().http_app()` with your own uvicorn, pass `proxy_headers=False` (uvicorn trusts the header from 127.0.0.1 by default).

## Filesystem route

`python -m uga.fs_gateway` (or `./scripts/run-contextbridge-fs.sh`) is a separate MCP server on port 8794. It gives agents file access inside the directories listed under `filesystem.roots` in `configs/contextbridge-fs.yaml`. The shipped config lists none, so the route refuses to start until you add some.

```sh
export CONTEXTBRIDGE_FS_AUTH_TOKEN="<a different strong secret>"
./scripts/run-contextbridge-fs.sh
```

`CONTEXTBRIDGE_FS_AUTH_TOKEN` follows the same rules as `MCP_AUTH_TOKEN` and must differ from it and from `CONTEXTBRIDGE_COMPUTER_TOKEN`; the route checks each of those that is set in its environment. Set `CONTEXTBRIDGE_FS_CONFIG` to use another config file. The config takes the same `name` (default `ContextBridge Files`) and `serve` keys as the gateway's, plus the `filesystem` section.

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

**Audit:** lines go to stderr and to `CONTEXTBRIDGE_FS_AUDIT_LOG` (or `serve.audit_log`, resolved against the config file's directory) with `route: "fs"`. As on the gateway, each request is one line, and `X-Forwarded-For` is ignored unless `serve.forwarded_allow_ips` lists the proxy. Paths are logged as the client sent them, with byte counts for reads and writes and the trash location for deletes. Refused paths are logged with `detail: "path_denied"`. Search events include `search_id` and result counts; patterns are logged only by length and hash.


**Known limits:** checks run before each operation, so another local process that swaps a symlink in between can still redirect it; only the final component is opened with `O_NOFOLLOW`. Likewise, a destination created between `move_file`'s check and the rename is replaced. Hard links that already exist inside a root are not detected.

## Computer route

The computer route serves files, search, commands, processes, and documents on the gateway's own machine and on enrolled remote devices. Every tool takes a `device` argument: `local` (the gateway's own machine, the default) or the name of an enrolled remote device (see [Remote devices](#remote-devices)). `list_devices` shows what is reachable. A tool is offered only when some device's policy enables it:

| Tool | Enabled on a device when |
|---|---|
| `list_directory`, `read_file`, `get_file_info`, `search_files`, `search_code`, `get_system_info` | always (read-only) |
| `write_file`, `edit_block`, `create_directory`, `move_file` | `filesystem.writable_roots` is non-empty |
| `delete_file` | writable roots, and `filesystem.delete` is `trash` (default) or `permanent` |
| `list_deleted`, `restore_deleted` | `filesystem.delete: trash` |
| `read_document` | always (read-only) |
| `write_document`, `edit_document`, `write_spreadsheet`, `edit_pdf` | `filesystem.writable_roots` is non-empty |
| `run_command`, `start_process`, `read_process_output`, `interact_with_process`, `force_terminate`, `list_sessions` | `commands.mode` is not `disabled` |
| `list_processes` | `processes.list: true` |
| `kill_process` | `processes.allow_kill: true` |
| `list_devices` | always |

### Running it

The computer route serves HTTP on a loopback address only. It will not start without its own token of at least 32 characters, a loopback `serve.host`, and a writable `serve.audit_log`.

```sh
export CONTEXTBRIDGE_COMPUTER_TOKEN="$(openssl rand -hex 32)"   # keep it in your secret manager
./scripts/run-computer.sh                                       # http://127.0.0.1:8791/mcp
```

Local MCP clients connect with the token as a bearer header. For example, in Claude Code:


```sh
claude mcp add --transport http contextbridge http://127.0.0.1:8791/mcp \
  --header "Authorization: Bearer $CONTEXTBRIDGE_COMPUTER_TOKEN"
```

There is no unauthenticated mode. Every MCP request is checked against the token.

### Authorization

These checks run on **every tool call**, at the moment it executes:

1. **Token scope.** The bearer token must carry the tool's scope: `computer:read` (file reading, search, system info, process listing, `list_devices`), `computer:write` (file changes), `computer:execute` (commands and sessions), or `computer:process` (`kill_process`). `auth.scopes` in the config sets what the token carries. Tools outside those scopes are hidden from the tool list and refused if called anyway.
2. **Device.** A remote (OAuth) client may only use the devices its grant names. The local token reaches every device. The device must exist and be online. Its policy must enable the tool. A remote device must also have been granted the tool's scope when it was paired.
3. **Policy checks.** The device's engine re-validates every path, command, working directory, and limit before acting. For a remote device, that's the agent on that machine, under its own policy.

### Policy

- **Paths.** Every path resolves through symlinks before it is checked, so neither `..` nor a symlink can escape `filesystem.roots`. Writes are allowed only inside `filesystem.writable_roots`. Any path with a component matching a `deny` glob (`.ssh`, `.env*`, `*.pem`, `*.kdbx`, and so on) is hidden from listings and searches and refused for reads and writes. The policy file and the audit log can never be written or moved through ContextBridge.
- **Limits.** Reads, writes, search results, and search time all have caps. Rewrites are atomic and preserve file mode. `edit_block` fails unless the match count is exactly what the caller expected.
- **Commands.** `allowlist` mode runs one program per call without a shell. The program must be on the allowlist, and pipes, redirects, `;` and `&&` are refused before anything runs. `unrestricted` mode runs through `bash -c`. The working directory must be inside a readable root. Every command has a hard timeout (`max_timeout_seconds` caps whatever the caller asks for), and a timed-out command is killed along with every process it started. Output is capped in memory, keeping the head and the tail. Variables that look like credentials (`*TOKEN*`, `*SECRET*`, `*PASSWORD*`, …) are removed from the child's environment, and all three route tokens (`MCP_AUTH_TOKEN`, `CONTEXTBRIDGE_FS_AUTH_TOKEN`, `CONTEXTBRIDGE_COMPUTER_TOKEN`) are always removed, whatever `env_strip` says.
- **Sessions.** `start_process` runs long or interactive programs in the background. Concurrent sessions are capped (`max_sessions`) and each is killed when it reaches `max_session_seconds`.
- **Deletes.** `delete_file` works only inside writable roots. It never deletes a root, a protected or hidden path, or a folder holding anything the file tools may not see (a `.ssh` or `.env` inside, say). A non-empty folder needs `recursive: true` and is capped at `max_delete_entries` (10,000).
  - **`delete: trash` (default):** the item moves to `.contextbridge-trash/<trash_id>/` in its writable root, beside a `<trash_id>.json` record of where it came from. `list_deleted` shows the trash and `restore_deleted` puts an item back, but no file tool can read, change, or empty the trash, so a client cannot make its own deletions permanent. Empty it on the host. The layout is the [filesystem route](#filesystem-route)'s, so a folder both routes serve has one trash.
  - **`delete: permanent`:** removes the item outright.
  - **`delete: disabled`:** removes the tool.

### Documents

`read_document` reads PDF, Word (`.docx`), and Excel (`.xlsx`, `.xlsm`) files; `read_file` is for text and points to it.
- **PDF:** text per page, with `pages` like `1-3,7` (50 pages per call).
- **Word:** the document as Markdown (headings, lists, and tables) plus a heading outline.
- **Excel:** sheet names and cell values for a `sheet` and `cell_range` (10,000 cells per call). `formulas: true` shows formulas instead of the values Excel last calculated.
- **`find`:** searches inside any of them and returns the pages, blocks, or cells that match.

Writing needs a writable root:
- **`write_document`:** creates or replaces a `.docx` or `.pdf` from simple Markdown (`#` headings, `-` and `1.` lists, `| a | b |` tables, paragraphs). PDFs use a Unicode font when the machine has one (DejaVu, Segoe UI, or Arial).
- **`edit_document`:** replaces exact text in a `.docx` (body, tables, headers, and footers). Like `edit_block`, it fails unless the match count is exactly what the caller expected. Formatting is kept when a match sits inside one formatted run; a match spanning runs takes the paragraph's first run's formatting. Text inside hyperlinks and fields is not matched.
- **`write_spreadsheet`:** writes rows of values into a sheet starting at `start_cell`, creating the `.xlsx` or the sheet if needed and keeping everything else. A string starting with `=` is stored as a formula. New workbooks must be `.xlsx`; existing `.xlsm` files keep their macros.
- **`edit_pdf`:** deletes, rotates, or inserts pages (from another PDF), in place or into `output_path`.

Documents go through the same path policy as every file tool. Files over `max_document_bytes` (20 MiB) are not opened. Word and Excel files are checked for zip bombs before parsing, and XML is parsed without entity expansion. The libraries (pypdf, python-docx, openpyxl, reportlab, defusedxml) are dependencies. A device without them doesn't offer the document tools.

**Know the boundary.** The command allowlist controls *which programs* run, not *what they touch*. `git diff --no-index` can read any file the OS user can, for example, and allowing a shell or an interpreter makes allowlist mode equivalent to unrestricted. The filesystem deny list applies to the file tools, not to commands. For a hard boundary, run the computer route as a dedicated OS user that can only reach what you intend to share.

### Audit trail

Each tool call writes a sequence of JSONL events that share a `request_id`:

| Event | Meaning |
|---|---|
| `requested` | The call arrived, with its arguments. Always written first. |
| `denied` | Authentication, scope, or policy refused it. Nothing ran. |
| `failed` | Refused before anything ran for another reason, such as bad input or a missing file. |
| `started` | Every check passed and the operation is about to touch the machine (resolved path, or argv and cwd). |
| `completed` | The operation finished. `success` says whether it achieved its goal: for commands, exit code 0 and no timeout. A command that ran and exited 1 is `completed` with `success: false`. |
| `exited` | A background session's process ended, with its exit code. |

`requested` also records which `listener` the call came in on (`local` or `remote`), and the later events carry the caller's `client`, which is the OAuth client id for remote calls. A `service_started` event records the policy and tool surface at startup. The audit log fails closed: if the `requested` or `started` event can't be written, the operation does not run. File content and stdin are logged only as a size and a hash, never the text.

## Remote devices

Other machines join as **devices**. Each runs a small agent that dials *out* to the gateway, so no machine needs an inbound port. The agent enforces its own policy file and keeps its own audit log. A compromised gateway still cannot make a device do more than that device's own config allows.

```
 MCP client ──HTTP+token──▶ gateway (Friday) ◀──WSS, outbound──  agent (Thanatos)
            127.0.0.1:8791   agents listener    Ed25519 identity   own policy + audit
                             LAN/Tailscale IP   pinned TLS cert
```

### Setting up a device

On the gateway host, enable the `agents` section of `configs/computer.yaml`:
- set `enabled: true`;
- set `host` to the gateway's LAN or Tailscale IP;
- keep `tls_cert`, `tls_key` and `registry` pointing at files under `state/`.

Then:

```sh
contextbridge-admin --config configs/computer.yaml tls-init --hostname friday --ip 100.101.102.103
contextbridge-admin --config configs/computer.yaml pair thanatos            # prints a one-time code + fingerprint
./scripts/run-computer.sh                                                   # gateway with the agent listener
```

On the device, copy `configs/agent.yaml` and set:
- `name`;
- `gateway.url` (`wss://<gateway IP>:8792`);
- `gateway.fingerprint` (from the `pair` output);
- the machine's own `filesystem` / `commands` / `processes` policy.

Then:

```sh
./scripts/run-agent.sh enroll --code ABCD-EFGH-IJKL-MNOP   # once: creates the device key (identity file, mode 0600)
./scripts/run-agent.sh                                     # stays connected, reconnects with backoff
```

Manage devices from the gateway host:

```sh
contextbridge-admin --config configs/computer.yaml devices
contextbridge-admin --config configs/computer.yaml revoke thanatos   # takes effect on the next call
```

Pairing is deliberately an admin CLI on the gateway host and not an MCP tool, so holding the MCP token never lets anyone enroll a new machine.

### How the channel is secured

- **Enrollment.** `pair` issues a random 80-bit code that is stored only as a hash, expires (15 minutes by default), and works once. The code fixes the device's name and scopes. The agent generates an Ed25519 key, and only the public half is sent and registered.
- **Authentication on every connection.** The gateway sends a fresh 32-byte nonce. The agent signs it, bound to the device id and the gateway id. Unknown, revoked, or wrongly signed devices are refused. Agents refuse a gateway whose id differs from the one they enrolled with.
- **Encryption.**
  - **TLS rules.** The listener must use TLS unless it is on loopback. Agents require `wss://` unless the gateway is on the same machine.
  - **Certificate pinning.** Agents check the gateway certificate's SHA-256 fingerprint before sending anything.
  - **Allowed bind addresses.** The listener binds only a specific loopback, LAN, or overlay (e.g. Tailscale) address. `0.0.0.0`, `::`, public IPs, and hostnames are refused.
- **Replay protection.** Calls carry a sequence number that must increase on each connection, and a request id the agent never accepts twice.
- **Liveness.** Agents send heartbeats. A device that misses three is dropped and shown offline, and its pending calls fail. Agents reconnect with exponential backoff (reset once a connection is accepted, so a blip after a long outage is retried within a second) and stop permanently once revoked.
- **One connection per device.** An agent refuses to start while another agent with the same identity file is running on that machine. If a second agent holding the same key connects anyway, the gateway pings the established connection: while it answers, the newcomer is refused (`already_connected`, retried with backoff) and the established connection keeps serving. A connection that does not answer within 5 seconds is replaced, so a restarted agent is never locked out by a half-open one.
- **Revocation.** `revoke` marks the device in the registry. The gateway refuses the next call to it and drops its live connection within a second.
- **Secrets stay hidden.** The local device can never read the TLS private key or the device registry, and an agent can never read its own identity file.
- **Audit on both sides.**
  - **Shared request ids.** A remote call carries the same `request_id` in the gateway's audit log and the agent's.
  - **Gateway events.** The gateway's log also records `device_enrolled`, `device_connected`, `device_disconnected`, `device_auth_failed`, `device_duplicate_refused`, `device_revoked`, and `device_heartbeat_lost`.
  - **`started` comes from the agent.** The agent reports `started` only after its own checks pass and its own log has recorded it.

### Windows devices (Thanatos)

The agent runs natively on Windows 10/11 with Python 3.11+. No WSL and no Node are needed.

```powershell
git clone https://github.com/Deep-Sixed/ContextBridge C:\ContextBridge
cd C:\ContextBridge
py -3 -m venv .venv
.venv\Scripts\python -m pip install -e .
copy configs\agent.windows.yaml configs\agent.yaml     # then set name, gateway.url, gateway.fingerprint, policy
.\scripts\run-agent.ps1 enroll -Code ABCD-EFGH-IJKL-MNOP   # once
.\scripts\install-agent.ps1                                # elevated PowerShell; or -AtLogOn without elevation
```

**Running as a scheduled task.** `install-agent.ps1` registers a scheduled task that runs the agent as *your* account, never SYSTEM, so commands have exactly your permissions within the agent's policy.
- **Default:** starts at boot whether or not you are signed in. It uses S4U, so no password is stored, but registering it needs an elevated shell.
- **`-AtLogOn`:** starts at sign-in instead, and needs no elevation.
- **Either way:** a second trigger repeats every minute from installation on, so an agent that exits is relaunched within a minute; a running one is left alone. To keep the agent stopped, disable the task (`Disable-ScheduledTask`); stopping it lasts only until the next repeat.
- **Logs:** go to `audit\agent.log`, plus the agent's audit log.
- **Removal:** `-Uninstall`.

**What changes on Windows:**
- **Process trees.** Every command runs inside a Windows Job Object. A timeout, `force_terminate`, or `kill` ends the command and everything it started. When a command exits, anything it left running in the background is ended too. If the agent itself is stopped, even by Task Scheduler, every process it started goes with it. Commands run without a console window.
- **Allowlist mode.** Programs must be `.exe`/`.com` files found on `PATH`. The current directory is never searched. Names are case-insensitive (`git` matches `Git.EXE`).
  - **Not programs:** `cmd.exe` built-ins (`dir`, `type`, `echo`) aren't programs, so they can't be allowlisted.
  - **Refused:** `.bat`/`.cmd` scripts, because `cmd.exe` re-parses their arguments, which allows command injection.
  - **Quoting:** command lines are split with Windows rules, so `git -C "C:\Program Files\repo" status` works as written.
- **Unrestricted mode.** `commands.shell` picks the shell: `powershell` (the default), `pwsh`, or `cmd`.
  - **PowerShell:** scripts are passed with `-EncodedCommand`, so quoting is never mangled, and output is forced to UTF-8.
  - **cmd:** receives the command line verbatim.
- **Paths.** Windows silently reinterprets some names, and those could slip past deny patterns, so they are refused:
  - alternate data streams (`notes.md:secret`, `.env::$DATA`);
  - device names (`CON`, `NUL`, `COM1`, …);
  - names ending in a dot or space (`.env.` opens `.env`);
  - `\\?\` / `\\.\` device paths;
  - drive-relative paths (`C:file`).

  Deny patterns ignore case. Windows adds its own defaults: registry hives, DPAPI and credential stores (`Protect`, `Credentials`, `Vault`), browser secrets, `*.ppk`, and `.azure`.
- **Text files.** UTF-16 files (what Windows PowerShell's `>` writes) and UTF-8 files with a BOM are read, searched, and edited as text. Edits keep the file's encoding and BOM. Command output that isn't UTF-8 is decoded with the console code page.
- **Identity key.** The enrolled key file's ACL is reduced to your account and SYSTEM, with inherited access removed. If that fails, enrollment stops instead of leaving the key readable.
- **Processes.** `kill_process` refuses critical Windows processes (`lsass`, `csrss`, `winlogon`, …), even with `allow_kill: true`.

CI runs the whole suite on `windows-latest` as well as Ubuntu. That includes the gateway-and-agent tests and the CLI end-to-end test, plus Windows-only tests for job objects, alternate data streams, `.bat` refusal, ACLs, and the PowerShell and cmd shells.

## Remote MCP clients (ChatGPT, Claude)

ChatGPT and Claude reach MCP servers from their own clouds, so they need a public HTTPS URL and OAuth. ContextBridge provides both without a third-party identity provider (no Authentik, no hosted relay). The `remote` section of the gateway config adds a second MCP endpoint on its own loopback port. It accepts only OAuth access tokens, and a TLS tunnel publishes it.

```
 Claude / ChatGPT ──HTTPS──▶ tunnel (e.g. Tailscale Funnel) ──▶ 127.0.0.1:8793  remote listener (OAuth)
 local MCP client ─────────────────────────────────────────────▶ 127.0.0.1:8791  local listener (static token)
                                     both share one set of devices, policies, sessions, and audit log
```

### Setting it up

1. **Fill in `remote`** in `configs/computer.yaml`:
   - `public_url`: the HTTPS origin the tunnel serves, for example `https://friday.<tailnet>.ts.net`.
   - `allow_scopes`: the most any remote client can ever be approved for. The default is `[computer:read]`.
   - `allow_devices`: which devices remote clients can be offered. The default is `[local]`; `"*"` means every enrolled device.
2. **Create the owner credentials.** Approving a remote client needs both a passphrase and a code from an authenticator app:

   ```sh
   contextbridge-admin --config configs/computer.yaml owner-init
   ```

   This prints a TOTP secret and an `otpauth://` URI to add to any authenticator app (`qrencode -t ansiutf8 '<uri>'` shows it as a QR code). It saves nothing until you type back a valid code.
3. **Enable it and start the tunnel.** Set `remote.enabled: true`, restart `run-computer.sh`, then run:

   ```sh
   tailscale funnel --bg 8793    # https://friday.<tailnet>.ts.net → http://127.0.0.1:8793
   ```

   Any TLS-terminating tunnel or reverse proxy works the same way. The gateway won't start remote mode until the owner credentials exist.
4. **Add the connector.** In Claude or ChatGPT, add a custom connector with the URL `https://friday.<tailnet>.ts.net/mcp`. The client registers itself and opens a ContextBridge consent page in your browser.
5. **Approve on the consent page.**
   - **Permissions.** Only `computer:read` starts ticked; anything more is a deliberate choice.
   - **Devices.** Tick which devices this client may use.
   - **Confirm.** Enter your passphrase and the current authenticator code.

### Managing clients

```sh
contextbridge-admin --config configs/computer.yaml oauth-clients              # who has access, with what
contextbridge-admin --config configs/computer.yaml oauth-revoke <client_id>   # or --all; next request fails
contextbridge-admin --config configs/computer.yaml oauth-unlock               # clear a consent lockout
```

### How the remote endpoint is secured

- **Owner consent on every authorization.** No client gets a token until you approve it on the consent page, which requires both the passphrase and a TOTP code.
  - **Single-use codes.** A TOTP code works only once.
  - **Lockout.** Five failures lock approvals for 15 minutes, and `oauth-unlock` clears the lock early. Anyone can trigger the lockout, but no one can get past it.
  - **Stored hashed.** The passphrase is kept only as an scrypt hash.
- **Least privilege.**
  - **Per-client grants.** Each client gets only the scopes and devices you tick.
  - **Config caps.** `remote.allow_scopes` and `remote.allow_devices` cap every grant. They are re-applied on every call, so narrowing the config and restarting narrows existing grants too.
  - **Hidden tools.** A tool the client can't use is hidden from its tool list and refused if called.
  - **Device policy still applies.** The device's own policy is enforced on top, exactly as for local calls.
- **Standard OAuth 2.1 for MCP.** The endpoint follows the MCP authorization spec:
  - **Discovery:** RFC 9728 protected-resource metadata and RFC 8414 authorization-server metadata.
  - **Registration:** Dynamic Client Registration, accepted only for HTTPS redirect URIs on `remote.allowed_redirect_hosts` (Claude and ChatGPT by default).
  - **PKCE:** S256 is required.
  - **Bound tokens:** tokens are tied to this server's `/mcp` resource.
- **Tokens.** Access tokens are opaque and short-lived (60 minutes by default). Refresh tokens rotate on every use, and presenting an already-rotated refresh token revokes the client's whole grant.
  - **Hashed at rest.** Codes and tokens are stored only as SHA-256 hashes, in a 0600 state file the file tools can never read.
  - **Live revocation.** A revocation from the CLI applies to the very next request.
- **Separate listeners.**
  - **Static token:** accepted only on the local listener.
  - **OAuth tokens:** accepted only on the remote listener.
  - **Host/Origin guard:** both listeners refuse requests whose `Host` or `Origin` isn't theirs, which blocks DNS rebinding. The remote listener also accepts the `public_url` name the tunnel forwards.
- **Hardened consent page.** It sends a strict CSP (no scripts, no framing, form posts only to itself and the client's redirect origin) and `no-store`. Every value on it is HTML-escaped.
- **Audit.** These events are written to the computer audit log: `oauth_client_registered`, `oauth_authorization_requested`, `oauth_consent_granted` / `_denied` / `_failed`, `oauth_token_issued`, `oauth_token_refreshed`, `oauth_refresh_reuse_detected`, and `oauth_grant_revoked`.

**Know the boundary.**
- **Commands can reach the secrets.** Granting a remote client `computer:execute` on a device lets it run whatever that device's command policy allows. If that includes a shell, it can read the gateway's secrets the same way any command could.
- **Keep remote clients read-only** unless you need more, and prefer `allowlist` mode.
- **Device names are visible.** The consent page shows the names of the devices you allow remotely to anyone who starts an authorization.

## Failover

ContextBridge serves every device through its own gateway, agents, permissions, and transport. The failover drill checks that on a live deployment, and CI checks it on a jailed one.

### The failover drill

Run the drill on the gateway host (Friday) with the ContextBridge gateway and the Thanatos agent running.

```sh
export CONTEXTBRIDGE_COMPUTER_TOKEN=...                                      # the local listener's token
contextbridge-failover --config configs/computer.yaml                        # read-only probes
contextbridge-failover --config configs/computer.yaml --write                # plus a write round trip
contextbridge-failover --config configs/computer.yaml --device thanatos --json
```

It prints PASS, FAIL, or skip for each check:

1. **The gateway answers.** It serves the computer tool surface over MCP, using your token.
2. **Every device is online and working.** By default that is `local` plus each enrolled agent; `--device` limits it. On each device the drill runs:
   - **Read checks:** system info, a directory listing, a file-name search, and a file read.
   - **Commands:** a harmless command (the first of `hostname`, `whoami`, `uname`, `pwd`, `date` the device's policy allows), run once directly and once as a session.
   - **Processes:** a process listing.
   - **Writes (`--write` only):** all inside `<first writable root>/.contextbridge-failover/`:
     - create, write, edit, move, read back, file info, and content search;
     - Word, PDF, and Excel files written and read back;
     - a file deleted and then restored from the trash, where the device keeps one.

No process is killed, and the only file deleted is the drill's own. The exit status is `0` for READY, `1` for NOT READY, and `2` if the drill could not run.

### What CI proves

`tests/test_failover.py` runs the whole deployment from its shipped entry points on Ubuntu and Windows: the knowledge gateway, the computer gateway with its agent and OAuth listeners, and an agent standing in for Thanatos. Everything runs inside a jail:

- **Tripwires:** `npx` and `node` programs come first on `PATH` and record any call.
- **Network jail:** `tests/failover_jail/sitecustomize.py` refuses and records every network destination off the machine, so no hosted relay, registry, or update check can be reached.

Then the test checks each of these:
- **Drill:** passes on both devices, including `--write`.
- **Every tool:** every computer tool works on both devices, apart from `list_windows` and `media_inventory`, which the test's device policies leave off.
- **Remote client:** a Claude/ChatGPT-style OAuth client reads from both devices and is refused anything it wasn't granted.
- **Knowledge route:** `search` and `fetch` work.
- **Restart:** after a gateway restart, the agent reconnects on its own and the OAuth token still works.
- **Audit:** both machines' audit logs show the same requests.
- **Isolation:** nothing touched a tripwire or the network.

### What the computer route leaves out

Some operations are deliberately not tools:
- **Changing policy** happens only on the host, so a client cannot widen its own access.
- **Usage statistics and call history** are in the host's JSONL audit log.
- **Collecting a pending result** is never needed: every call finishes within `call_timeout_seconds`.
- **Stopping an agent** is done on the host, with `contextbridge-admin revoke` or by stopping the agent's service.
- **The caller's identity** is recorded in the audit log but not returned to the client.

Beyond individual tools, the checklist in `docs/capability-roadmap.pdf` also lists capabilities the computer route does not have yet:
- **asynchronous, paged search** sessions;
- legacy **`.xls`** workbooks, images, and fetching URLs;
- the **synchronization** layer (transfer, sync, checksums, conflicts).

Native delete and the PDF, Word, and Excel tools arrived in phase 7 (see [Documents](#documents) and the **Deletes** policy above).

## Network exposure

No route depends on Authentik.
- **Knowledge route:** binds to loopback by default; do not set `serve.host` to a public interface. It has no OAuth front end; the remote endpoint serves only the computer route.
- **Filesystem route (8794):** binds to loopback by default, and the same `serve.host` rule applies. It has no OAuth front end either.
- **Computer MCP endpoints:** refuse any non-loopback address; there is no override.
  - **Local listener (8791):** accepts only the static token.
  - **Remote listener (8793):** accepts only OAuth tokens. It is meant to be published only through a TLS tunnel.
- **Agent listener:** TLS-only, limited to private addresses, and accepts only enrolled devices.

Do not forward ports 8790, 8791, 8792, or 8794 to the internet. Publish 8793 only through a TLS tunnel, and only once `owner-init` is done.

## Roadmap

1. ~~Independent local filesystem and terminal tools~~
2. ~~Local policy enforcement, execution limits, tests~~
3. ~~Remote agent transport and device registration (outbound agent connections, heartbeats, revocation)~~
4. ~~Windows agent for Thanatos (native agent, job-object process trees, scheduled-task install, Windows CI)~~
5. ~~Authenticated remote MCP endpoint for ChatGPT and Claude (OAuth front end, per-device permissions)~~
6. ~~Failover acceptance test (drill + jailed CI test)~~
7. ~~Native delete (trash with restore) and document tools (PDF, Word, Excel)~~

## Documentation

The PDFs in `docs/` are planning documents. The filesystem and computer routes implement the roadmap's filesystem operations; the filesystem route now also offers asynchronous file and content search. The computer route covers search, commands, processes, remote devices, documents (PDF, Word, Excel) and native recoverable delete. Synchronization remains unimplemented. The read-only knowledge route rejects these operations. The documents refer to Friday (Linux) and Thanatos (Windows).


- `docs/capability-roadmap.pdf` lists the capabilities ContextBridge targets, with an implementation checklist. The checklist is a blank tracker, not a status report. It is generated by `scripts/build-roadmap-pdf.py`.
- `docs/computer-use-linux-review.pdf` evaluates `agent-sh/computer-use-linux` as a Linux desktop-control engine for ContextBridge. It is generated by `scripts/build-review-pdf.py`.

Both scripts share `scripts/pdf_common.py`. To rebuild a PDF after editing its script (requires the DejaVu fonts; set `CONTEXTBRIDGE_FONT_DIR` if they are not in a standard font directory):

```sh
python3 -m pip install -e '.[docs]'
./scripts/build-roadmap-pdf.py
./scripts/build-review-pdf.py
```

## Status

The knowledge route is a standalone extraction from an archived UGA (Unidirectional Gateway Appliance) implementation. That is why the package is `uga`, environment variables start with `UGA_`, the gateway's default name is `Nexus UGA`, and its timeout errors say "Nexus Datacore". Authentication-front/sidecar deployments and systemd services were intentionally left out. No route is production-validated yet.

## License

ContextBridge is released under the MIT License; see [`LICENSE`](LICENSE).
