# ContextBridge

A self-hosted MCP gateway that gives AI assistants authenticated, policy-controlled access to your own computers. ContextBridge has no runtime dependency on any hosted relay: its own gateway, agents, and transport do the work.

It has two routes, each with its own server, port, and credential:

| Route | Module | Tools | Credential |
|---|---|---|---|
| Filesystem | `contextbridge.filesystem.gateway` | file tools inside configured directories (see [Filesystem route](#filesystem-route)) | `CONTEXTBRIDGE_FS_AUTH_TOKEN` |
| Computer | `contextbridge.computer` | files, search, documents, commands, sessions, processes, devices; opt-in window and media inventory | `CONTEXTBRIDGE_COMPUTER_TOKEN` |

Each route accepts only its own token, and each refuses to start if its token matches the other route's, when both are set in its environment.

The computer route can also serve ChatGPT, Claude, and other remote MCP clients through a second, OAuth-protected endpoint. Each client gets only the permissions and devices you approve for it (see [Remote MCP clients](#remote-mcp-clients-chatgpt-claude)).

## Installation

```sh
python3 -m pip install -e '.[test]'
python3 -m pytest        # includes acceptance tests that launch the gateways and an agent as real processes
```

ContextBridge requires Python 3.11+ and FastMCP 3.x (`fastmcp>=3,<4`). It has no runtime dependency on Node or npx, and the acceptance tests run both gateways in an environment without them.

`tests/test_fs.py` covers the filesystem operations and path rules, and `tests/test_fs_gateway.py` pins the filesystem route's MCP contract (tool set, annotations, schemas, reported version, default-deny for every other method) and starts its entrypoint. CI runs the whole suite on Ubuntu and Windows, with Python 3.11 against the oldest supported FastMCP (3.0.0) and Python 3.13 against the newest 3.x release.

## Filesystem route

`python -m contextbridge.filesystem.gateway` (or `./scripts/run-contextbridge-fs.sh`) is a separate MCP server on port 8794. It gives agents file access inside the directories listed under `filesystem.roots` in `configs/contextbridge-fs.yaml`. The shipped config lists none, so the route refuses to start until you add some.

```sh
export CONTEXTBRIDGE_FS_AUTH_TOKEN="<a different strong secret>"
./scripts/run-contextbridge-fs.sh
```

`CONTEXTBRIDGE_FS_AUTH_TOKEN` is required, must be at least 32 characters (for example `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`), and must differ from `CONTEXTBRIDGE_COMPUTER_TOKEN` when that is set. Set `CONTEXTBRIDGE_FS_CONFIG` to use another config file.

MCP clients connect over streamable HTTP to `http://127.0.0.1:8794/mcp` and send `Authorization: Bearer <CONTEXTBRIDGE_FS_AUTH_TOKEN>`. Every HTTP route requires the token, including `GET /`, which returns the service name, the MCP path, and the tool names. A request without a valid token gets `401` and is audited as `auth`.

| Setting | Default | Purpose |
| --- | --- | --- |
| `serve.host` | `127.0.0.1` | Listen address; keep it on loopback |
| `serve.port` | required | Listen port (`8794` in `configs/contextbridge-fs.yaml`) |
| `name` | `ContextBridge Files` | Server name reported in `serverInfo` and by `GET /` |
| `CONTEXTBRIDGE_FS_AUDIT_LOG` or `serve.audit_log` | unset | Audit log file (see **Audit** below) |
| `serve.forwarded_allow_ips` | unset | Proxy addresses whose `X-Forwarded-For` is trusted for the audited `peer` |
| `CONTEXTBRIDGE_MCP_TOOL_TIMEOUT_SECONDS` | `10` | Timeout for a tool call |
| `CONTEXTBRIDGE_MCP_METADATA_TIMEOUT_SECONDS` | `5` | Timeout for `initialize` and `tools/list` |
| `filesystem` | required | Roots and limits (below) |

Where a setting has both an environment variable and a config key, the environment variable wins. An unset, unparsable, or non-positive timeout falls back to the default. Relative paths in the config are resolved against the config file's directory.

Other MCP methods are default-deny: `resources/list`, `resources/templates/list` and `prompts/list` return empty lists, `ping` is answered, and every other request (for example `resources/read`, `prompts/get`, `logging/setLevel`) is rejected and audited. Error details are masked from clients.

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

Each search runs in its own worker process (`src/contextbridge/filesystem/search_worker.py`, started with `python -I`), so `stop_search` and `timeout_ms` (default 30000, at most 300000) stop it even inside a slow regular expression. On Linux and macOS the worker also sets an alarm a few seconds past its timeout, so it ends even if the server dies first. At most 4 searches run at once. The 10 most recent are kept in memory, and the oldest finished one is dropped to make room, so search ids are not kept across restarts. Searches are shared: every client with the route's token can list, page through and stop them.

**Deletion is recoverable:** each deleted item is kept under `.contextbridge-trash/<trash_id>/`, next to a `<trash_id>.json` file recording its original path. No tool can read, list, change or empty the trash; recover or purge items from the host.

**Limits:** `max_read_bytes` and `max_write_bytes` (1 MiB each by default) cap a response and a write, `max_list_entries` (1000) caps a listing, and `max_search_file_bytes` (10 MiB) is the largest file a content search reads. Text must be UTF-8; binary files are refused.

**Audit:** each MCP request except `ping`, and each HTTP request rejected by auth, is one JSON line with `route: "fs"`, written to stderr (prefixed `[fs audit] `) and, if set, to `CONTEXTBRIDGE_FS_AUDIT_LOG` (or `serve.audit_log`). The file is opened without following symlinks, must be a regular file, and is set to mode `0600`. Each line has a unique `request_id`. Denied tools and methods are logged with `detail: "policy_denied"` and without their arguments; requests rejected by bearer auth are logged as `tool: "auth"` with `missing_token`, `invalid_token`, or `forbidden`. Client-supplied strings are cut to 200 characters. The `peer` field is the TCP peer address; `X-Forwarded-For` is ignored unless `serve.forwarded_allow_ips` lists the proxy. Paths are logged as the client sent them, with byte counts for reads and writes and the trash location for deletes. Refused paths are logged with `detail: "path_denied"`. Search events include `search_id` and result counts; patterns are logged only by length and hash.

**Known limits:** checks run before each operation, so another local process that swaps a symlink in between can still redirect it; only the final component is opened with `O_NOFOLLOW`. Likewise, a destination created between `move_file`'s check and the rename is replaced. Hard links that already exist inside a root are not detected.

## Computer route

The computer route serves files, search, commands, processes, and documents on the gateway's own machine and on enrolled remote devices. Every tool takes a `device` argument: `local` (the gateway's own machine, the default) or the name of an enrolled remote device (see [Remote devices](#remote-devices)). `list_devices` shows what is reachable. A tool is offered only when some device's policy enables it:

| Tool | Enabled on a device when |
|---|---|
| `list_directory`, `read_file`, `get_file_info`, `search_files`, `search_code`, `get_system_info` | always (read-only) |
| `write_file`, `edit_block`, `create_directory`, `move_file` | `filesystem.writable_roots` is non-empty |
| `delete_file` | writable roots, and `filesystem.delete` is `trash` (default) or `permanent` |
| `list_deleted`, `restore_deleted` | writable roots, and `filesystem.delete: trash` |
| `read_document` | always (read-only) |
| `write_document`, `edit_document`, `write_spreadsheet`, `edit_pdf` | `filesystem.writable_roots` is non-empty |
| `run_command`, `start_process`, `read_process_output`, `interact_with_process`, `force_terminate`, `list_sessions` | `commands.mode` is not `disabled` |
| `list_processes` | `processes.list: true` |
| `kill_process` | `processes.allow_kill: true` |
| `list_windows` | `desktop.observe: true` (see [Desktop and media inventory](#desktop-and-media-inventory)) |
| `media_inventory` | `media.discover: true` |
| `list_devices` | always |

### Running it

The computer route serves HTTP on a loopback address only. It will not start without its own token of at least 32 characters, a loopback `serve.host`, and a writable `serve.audit_log`.

```sh
export CONTEXTBRIDGE_COMPUTER_TOKEN="$(openssl rand -hex 32)"   # keep it in your secret manager
./scripts/run-computer.sh                                       # http://127.0.0.1:8791/mcp
```

Set `CONTEXTBRIDGE_COMPUTER_CONFIG` to use another config file.

Local MCP clients connect with the token as a bearer header. For example, in Claude Code:

```sh
claude mcp add --transport http contextbridge http://127.0.0.1:8791/mcp \
  --header "Authorization: Bearer $CONTEXTBRIDGE_COMPUTER_TOKEN"
```

There is no unauthenticated mode. Every MCP request is checked against the token.

### Authorization

These checks run on **every tool call**, at the moment it executes:

1. **Token scope.** The bearer token must carry the tool's scope: `computer:read` (file reading, search, system info, process listing, `list_devices`), `computer:write` (file changes), `computer:execute` (commands and sessions), `computer:process` (`kill_process`), `desktop:observe` (`list_windows`), or `media:discover` (`media_inventory`). `auth.scopes` in the config sets what the token carries; without it the token carries all six, but the shipped `configs/computer.yaml` grants only the four `computer:*` scopes. Tools outside those scopes are hidden from the tool list and refused if called anyway.
2. **Device.** A remote (OAuth) client may only use the devices its grant names. The local token reaches every device. The device must exist and be online. Its policy must enable the tool. A remote device must also have been granted the tool's scope when it was paired.
3. **Policy checks.** The device's engine re-validates every path, command, working directory, and limit before acting. For a remote device, that's the agent on that machine, under its own policy.

### Policy

- **Paths.** Every path resolves through symlinks before it is checked, so neither `..` nor a symlink can escape `filesystem.roots`. Writes are allowed only inside `filesystem.writable_roots`. Any path with a component matching a `deny` glob (`.ssh`, `.env*`, `*.pem`, `*.kdbx`, and so on) is hidden from listings and searches and refused for reads and writes. The policy file and the audit log can never be written or moved through ContextBridge.
- **Limits.** Reads, writes, search results, and search time all have caps. A `search_code` regular expression is matched in a separate worker process that is killed when `max_search_seconds` runs out, so a slow pattern cannot stall the gateway or an agent. Rewrites are atomic and preserve file mode. `edit_block` fails unless the match count is exactly what the caller expected.
- **Commands.** `allowlist` mode runs one program per call without a shell. The program must be on the allowlist, and pipes, redirects, `;` and `&&` are refused before anything runs. `unrestricted` mode runs through a shell: `bash -c` by default (PowerShell on Windows), or whatever `commands.shell` names (`bash`, `sh`, `powershell`, `pwsh`, `cmd`, or an argv list). The working directory must be inside a readable root. Every command has a hard timeout (`max_timeout_seconds` caps whatever the caller asks for), and a timed-out command is killed along with every process it started. Output is capped in memory, keeping the head and the tail. Variables that look like credentials (`*TOKEN*`, `*SECRET*`, `*PASSWORD*`, …) are removed from the child's environment, and both route tokens (`CONTEXTBRIDGE_FS_AUTH_TOKEN`, `CONTEXTBRIDGE_COMPUTER_TOKEN`) are always removed, whatever `env_strip` says, as is the retired `MCP_AUTH_TOKEN`. On Linux every ContextBridge server also marks itself non-dumpable at startup, so a command cannot read the tokens back out of the server's own `/proc/<pid>/environ` (`ps e` shows exactly that); as a side effect the servers write no core dumps and attaching a debugger to one needs root.
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

**Know the boundary.** The command allowlist controls *which programs* run, not *what they touch*. `git diff --no-index` can read any file the OS user can, for example. Allowing a program that can run other programs makes allowlist mode equivalent to unrestricted: a shell, an interpreter, or git, whose `-c` options and aliases run any command, so the example configs leave git out. They also leave out `ps`: `ps e` prints the environment of every process the OS user runs, and that is where other programs keep their tokens and API keys (the servers warn at startup if `ps` is on the allowlist; `list_processes` shows processes without their environment). The filesystem deny list applies to the file tools, not to commands. For a hard boundary, run the computer route as a dedicated OS user that can only reach what you intend to share.

### Desktop and media inventory

Both tools are off by default and only report; neither captures the screen, sends input, records, or plays anything. Each needs the device policy switch and the token scope.

- **`list_windows`** (`desktop.observe: true`, scope `desktop:observe`) returns up to 200 visible windows, each with an `id` and a `title` cut to 256 characters. Window titles can reveal what you are working on. On Windows it lists visible top-level windows of the interactive desktop. On Linux it needs a graphical session (`DISPLAY` or `WAYLAND_DISPLAY`) and `wmctrl`; without them the call fails.
- **`media_inventory`** (`media.discover: true`, scope `media:discover`) returns device-count hints, never opening a device: on Linux the number of `/dev/video*` nodes, on Windows the number of audio input and output devices. Counts it cannot get are `null`, and a count is not proof that a device works.

`docs/phase-2-desktop-plan.md` describes the planned next steps (session discovery, screen capture, input), none of which exist yet.

### MCP servers on a device (federation)

A device can also run other MCP servers, such as agent-desktop for desktop automation or Playwright MCP for a browser, and offer their tools through the same ContextBridge connection. ChatGPT or Claude then needs one connector, not one per server per machine.

List the servers in that machine's own config (`agent.yaml` on a device, `computer.yaml` for `local`):

```yaml
mcp_servers:
  desktop:                       # server name: lowercase letters, digits, '-'
    command: agent-desktop
    args: [mcp]
    scope: computer:execute      # default; the token and the device grant must both carry it
    tool_scopes:                 # optional: other scopes for single tools (check names with list_devices)
      desktop_snapshot: desktop:observe
      desktop_screenshot: desktop:observe
    # tools: [desktop_snapshot, desktop_click]   # optional allowlist of the server's own tool names
    # env: {NAME: value}                         # added to the credential-stripped environment
    # timeout_seconds: 120                       # per call, at most 600
  browser:
    command: npx
    args: ["-y", "@playwright/mcp@<exact version>"]   # pin a version; never @latest
```

How it works:
- The engine starts each server over stdio when the agent (or gateway) starts, lists its tools, and reports them to the gateway. A server that fails to start is logged and left out; one that exits is started again on its next call.
- Each tool is offered as `<server>_<tool>`, and a tool already named with that prefix keeps its name, so agent-desktop's `desktop_snapshot` stays `desktop_snapshot`. Names never replace a built-in tool. A tool that has its own `device` argument is skipped.
- Callers see each tool once, with an added `device` argument. It defaults to the only device offering the tool (or `local`), and is required when several devices offer it. `list_devices` shows each device's `mcp_tools`.
- Only the machine's own config can add a server. The gateway can call the tools a device reports; it cannot start a program or change the list.
- Every call is checked like a built-in one: the caller's token, the device's registry grant, and the server's scope. It is audited as `requested` → `started` → `completed` on the gateway and the device. Arguments are logged only as a size and a hash, and `completed` records `success: false` when the server reports an error.
- Servers get the same credential-stripped environment as commands. They run with the agent's own account and privileges, so a server is as powerful as what it can do there: grant `computer:execute` (or the scope you chose) only to devices and clients that should drive it.
- Text, images, and structured results are passed through, up to 12 MB per result.

Desktop servers need a desktop: on Windows run the agent with the at-logon task (`install-agent.ps1`), not a boot-time task with no interactive session. Clients see new tools when they next list tools; this phase does not yet push change notifications, MCP resources, or prompts.

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

`requested` also records which `listener` the call came in on (`local` or `remote`), and the later events carry the caller's `client`, which is the OAuth client id for remote calls. A `service_started` event records the policy and tool surface at startup. The audit log fails closed: if the `requested` or `started` event can't be written, the operation does not run. File content and stdin are logged only as a size and a hash, never the text. Audit logs record commands and paths verbatim, so they are created readable only by their owner (mode 0600), and an existing log is tightened to 0600 at startup.

## Remote devices

Other machines join as **devices**. Each runs a small agent that dials *out* to the gateway, so no machine needs an inbound port. The agent enforces its own policy file and keeps its own audit log. A compromised gateway still cannot make a device do more than that device's own config allows.

The steps below connect devices over Tailscale. To run the gateway on a VPS and let agents connect from any network through Cloudflare Tunnel instead, without Tailscale, see [docs/vps-gateway.md](docs/vps-gateway.md).

```
 MCP client ──HTTP+token──▶ gateway (Friday) ◀──WSS, outbound──  agent (Thanatos)
            127.0.0.1:8791   agents listener    Ed25519 identity   own policy + audit
                             Tailscale IP       pinned TLS cert
```

### Setting up a device

On the gateway host, enable the `agents` section of `configs/computer.yaml`:
- set `enabled: true`;
- set `host` to the gateway's Tailscale IP;
- set `tailnet_node_ids` to the Tailscale node IDs of the machines allowed to connect (`Peer[*].ID` in `tailscale status --json` on the gateway). With a non-loopback `host` and an empty list the gateway won't start, and `contextbridge-admin tls-init` and `pair` refuse to run, so set this before the commands below;
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
- `gateway.fingerprint` (from the `pair` output), or `gateway.ca_file` if the gateway's certificate is signed by a CA you run;
- the machine's own `filesystem` / `commands` / `processes` policy.

Then:

```sh
./scripts/run-agent.sh enroll --code ABCD-EFGH-IJKL-MNOP   # once: creates the device key (identity file, mode 0600)
./scripts/run-agent.sh                                     # stays connected, reconnects with backoff
```

Set `CONTEXTBRIDGE_AGENT_CONFIG` to use another config file.

Manage devices from the gateway host:

```sh
contextbridge-admin --config configs/computer.yaml devices
contextbridge-admin --config configs/computer.yaml revoke thanatos   # takes effect on the next call
```

Pairing is deliberately an admin CLI on the gateway host and not an MCP tool, so holding the MCP token never lets anyone enroll a new machine.

### How the channel is secured

- **Tailnet admission.** Unless the listener is on loopback, every connection is checked against the gateway's own `tailscale status --json` before anything else: the peer must be online and its Tailscale IP must belong to exactly one node in `agents.tailnet_node_ids`. A machine reaching the listener over a plain LAN address is refused, as is everything when `tailscale` can't be queried.
- **Enrollment.** `pair` issues a random 80-bit code that is stored only as a hash, expires (15 minutes by default), and works once. The code fixes the device's name and scopes. The agent generates an Ed25519 key, and only the public half is sent and registered.
- **Authentication on every connection.** The gateway sends a fresh 32-byte nonce. The agent signs it, bound to the device id and the gateway id. Unknown, revoked, or wrongly signed devices are refused. Agents refuse a gateway whose id differs from the one they enrolled with.
- **Encryption.**
  - **TLS rules.** The listener must use TLS unless it is on loopback. Agents require `wss://` unless the gateway is on the same machine.
  - **Certificate pinning.** With `gateway.fingerprint` set, agents check the gateway certificate's SHA-256 fingerprint before sending anything. Without it, the certificate and host name are verified against `gateway.ca_file`, or the system's CA store if that is unset too.
  - **Allowed bind addresses.** The listener binds only a specific private address. `0.0.0.0`, `::`, public IPs, and hostnames are refused. In practice that means loopback (an agent on the gateway's own machine) or the gateway's Tailscale IP: a LAN address passes this check, but tailnet admission then refuses every agent that connects to it.
- **Replay protection.** Calls carry a sequence number that must increase on each connection, and a request id the agent never accepts twice.
- **Liveness.** Agents send heartbeats. A device that misses three is dropped and shown offline, and its pending calls fail. Agents reconnect with exponential backoff (reset once a connection is accepted, so a blip after a long outage is retried within a second) and stop permanently once revoked.
- **One connection per device.** An agent refuses to start while another agent with the same identity file is running on that machine. If a second agent holding the same key connects anyway, the gateway pings the established connection: while it answers, the newcomer is refused (`already_connected`, retried with backoff) and the established connection keeps serving. A connection that does not answer within 5 seconds is replaced, so a restarted agent is never locked out by a half-open one.
- **Revocation.** `revoke` marks the device in the registry. The gateway refuses the next call to it and drops its live connection within a second.
- **Secrets stay hidden.** The local device can never read the TLS private key or the device registry, and an agent can never read its own identity file.
- **Audit on both sides.**
  - **Shared request ids.** A remote call carries the same `request_id` in the gateway's audit log and the agent's.
  - **Gateway events.** The gateway's log also records `device_enrolled`, `device_enroll_rejected`, `device_connected`, `device_disconnected`, `device_auth_failed`, `device_duplicate_refused`, `device_revoked`, `device_heartbeat_lost`, and `tailnet_admission_denied`.
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
- **`-Elevated`:** runs the task with your full administrator token (run level Highest) instead of the standard one, so commands can change system settings, services and protected files. It needs an elevated shell and an account in the Administrators group, and combines with either trigger. Reinstalling without it goes back to a standard token. Pass `-ExpectElevated` to `check-agent.ps1` so the health check expects it.
- **Either way:** a second trigger repeats every minute from installation on, so an agent that exits is relaunched within a minute; a running one is left alone. To keep the agent stopped, disable the task (`Disable-ScheduledTask`); stopping it lasts only until the next repeat.
- **Logs:** go to `audit\agent.log`, plus the agent's audit log.
- **Removal:** `-Uninstall`.

**What changes on Windows:**
- **Process trees.** Every command runs inside a Windows Job Object. A timeout, `force_terminate`, or `kill` ends the command and everything it started. When a command exits, anything it left running in the background is ended too. If the agent itself is stopped, even by Task Scheduler, every process it started goes with it. Commands run without a console window.
- **Allowlist mode.** Programs must be `.exe`/`.com` files found on `PATH`. The current directory is never searched. Names are case-insensitive (`whoami` matches `WHOAMI.EXE`).
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
 Claude / ChatGPT ──HTTPS──▶ Cloudflare Tunnel ────────▶ 127.0.0.1:8793  remote listener (OAuth)
 local MCP client ─────────────────────────────────────────────▶ 127.0.0.1:8791  local listener (static token)
                                     both share one set of devices, policies, sessions, and audit log
```

### Setting it up

1. **Fill in `remote`** in `configs/computer.yaml`:
   - `public_url`: the **exact public HTTPS origin** the tunnel serves, for example `https://mcp.example.com` (no `/mcp` path). The remote Host/Origin guard accepts that hostname, and OAuth discovery and authorization URLs use it. Update this setting whenever you rename the public hostname.
   - `allow_scopes`: the most any remote client can ever be approved for. The default is `[computer:read]`.
   - `allow_devices`: which devices remote clients can be offered. The default is `[local]`; `"*"` means every enrolled device.
2. **Create the owner credentials.** Approving a remote client needs both a passphrase and a code from an authenticator app:

   ```sh
   contextbridge-admin --config configs/computer.yaml owner-init
   ```

   This prints a TOTP secret and an `otpauth://` URI to add to any authenticator app (`qrencode -t ansiutf8 '<uri>'` shows it as a QR code). It saves nothing until you type back a valid code.
3. **Enable the remote listener and publish it through Cloudflare Tunnel.** Set `remote.enabled: true`, set `remote.public_url` to the HTTPS hostname you will publish, and restart the gateway. The gateway won't start remote mode until the owner credentials exist. In Cloudflare, create a tunnel and configure a **Published application** route for the same hostname, with a blank path and a service URL of `http://127.0.0.1:8793` (or your configured `remote.port`). Leave ContextBridge OAuth enabled. See [Cloudflare Tunnel setup and verification](#cloudflare-tunnel-with-a-custom-domain).
4. **Add the connector.** In Claude or ChatGPT, add a custom connector with the URL `<public_url>/mcp`. The client registers itself and opens a ContextBridge consent page in your browser.
5. **Approve on the consent page.**
   - **Permissions.** Only `computer:read` starts ticked; anything more is a deliberate choice.
   - **Devices.** Tick which devices this client may use.
   - **Confirm.** Enter your passphrase and the current authenticator code.

### Cloudflare Tunnel with a custom domain

A Cloudflare Tunnel can publish the OAuth listener without opening an inbound port. For a host such as `mcp.example.com`:

1. In Cloudflare, create a remotely managed tunnel and run its `cloudflared` connector on the **same host as the ContextBridge gateway**. Store the tunnel token only in the connector's service configuration; never commit or paste it into logs.
2. Add a **Published application** route: hostname `mcp.example.com`, **path left blank**, service URL `http://127.0.0.1:8793` (or the actual `remote.port`). Cloudflare should create the tunnel DNS record. Do not make a second DNS record manually.
3. Set `remote.public_url: https://mcp.example.com` in the **deployment's** gateway YAML, then restart only the ContextBridge gateway. The published URL must match the request's `Host` header; otherwise the Host/Origin guard intentionally returns **HTTP 421 Misdirected Request**. Do not disable the guard to work around a hostname migration.
4. Before changing the client connector, verify:
   - `curl -i https://mcp.example.com/mcp` → **401 Unauthorized** without a token, with a `WWW-Authenticate` metadata URL on the new origin.
   - `curl -i https://mcp.example.com/.well-known/oauth-protected-resource/mcp` → **200**; `resource` is `https://mcp.example.com/mcp`.
   - `curl -i https://mcp.example.com/.well-known/oauth-authorization-server` → **200**; `issuer`, `authorization_endpoint`, `token_endpoint`, and `registration_endpoint` use the new origin.
5. Point the ChatGPT/Claude connector to `https://mcp.example.com/mcp` and complete OAuth consent. Keep the gateway's built-in authentication enabled. A separate Cloudflare Access browser challenge can interrupt MCP OAuth, so test any additional access policy before enforcing it.

**Hostname migration / 421 troubleshooting:** compare the Host header sent by the tunnel with `remote.public_url`. To diagnose locally without weakening the guard, try `curl -i -H 'Host: mcp.example.com' http://127.0.0.1:8793/mcp`: **401** means the new name is accepted, **421** means the running gateway still rejects it. Back up the deployment config before changing it and restart the gateway to reload the settings. A healthy tunnel, DNS record, or wildcard TLS certificate alone does not fix a gateway Host mismatch. Changing `public_url` changes the MCP resource that access tokens are bound to, so tokens issued for the old name stop working: reconnect each ChatGPT or Claude connector after the change, and remove its old registration with `contextbridge-admin oauth-revoke`.

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
- **Tokens.** Access tokens are opaque and short-lived (60 minutes by default). Refresh tokens rotate on every use, and presenting an already-rotated refresh token revokes the client's whole grant. A client that doesn't refresh for `refresh_token_days` (30 by default) must be approved again.
  - **Hashed at rest.** Codes and tokens are stored only as SHA-256 hashes, in a 0600 state file the file tools can never read.
  - **Live revocation.** A revocation from the CLI applies to the very next request.
- **Separate listeners.**
  - **Static token:** accepted only on the local listener.
  - **OAuth tokens:** accepted only on the remote listener.
  - **Host/Origin guard:** both listeners refuse requests whose `Host` or `Origin` isn't theirs, which blocks DNS rebinding. The remote listener also accepts the `public_url` name the tunnel forwards.
- **Hardened consent page.** It sends a strict CSP (no scripts, no framing, form posts only to itself and the client's redirect origin) and `no-store`. Every value on it is HTML-escaped.
- **Audit.** These events are written to the computer audit log: `oauth_client_registered`, `oauth_authorization_requested`, `oauth_consent_granted` / `_denied` / `_failed`, `oauth_token_issued`, `oauth_token_refreshed`, `oauth_refresh_reuse_detected`, and `oauth_grant_revoked`.

**Know the boundary.**
- **Commands can reach the secrets.** Granting a remote client `computer:execute` on a device lets it run whatever that device's command policy allows. If that includes a shell, it can read the gateway's secrets the same way any command could, and a shell is not the only way: see the note on `ps` in the computer route's own "Know the boundary".
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

`tests/test_failover.py` runs the whole deployment from its shipped entry points on Ubuntu and Windows: the computer gateway with its agent and OAuth listeners, and an agent standing in for Thanatos. Everything runs inside a jail:

- **Tripwires:** `npx` and `node` programs come first on `PATH` and record any call.
- **Network jail:** `tests/failover_jail/sitecustomize.py` refuses and records every network destination off the machine, so no hosted relay, registry, or update check can be reached.

Then the test checks each of these:
- **Drill:** passes on both devices, including `--write`.
- **Every tool:** every computer tool works on both devices, apart from `list_windows` and `media_inventory`, which the test's device policies leave off.
- **Remote client:** a Claude/ChatGPT-style OAuth client reads from both devices and is refused anything it wasn't granted.
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
- **Filesystem route (8794):** binds to loopback by default; do not set `serve.host` to a public interface. It has no OAuth front end; the remote endpoint serves only the computer route.
- **Computer MCP endpoints:** refuse any non-loopback address; there is no override.
  - **Local listener (8791):** accepts only the static token.
  - **Remote listener (8793):** accepts only OAuth tokens. It is meant to be published only through a TLS tunnel.
- **Agent listener:** limited to loopback or private addresses, and accepts only enrolled devices. On a private address it is TLS-only and agents must connect from a Tailscale node listed in `agents.tailnet_node_ids`. On loopback it can be published through Cloudflare Tunnel, which provides the TLS (see [docs/vps-gateway.md](docs/vps-gateway.md)).

Do not forward ports 8791, 8792, or 8794 to the internet. Publish 8793 only through a TLS tunnel, and only once `owner-init` is done.

## Roadmap

1. ~~Independent local filesystem and terminal tools~~
2. ~~Local policy enforcement, execution limits, tests~~
3. ~~Remote agent transport and device registration (outbound agent connections, heartbeats, revocation)~~
4. ~~Windows agent for Thanatos (native agent, job-object process trees, scheduled-task install, Windows CI)~~
5. ~~Authenticated remote MCP endpoint for ChatGPT and Claude (OAuth front end, per-device permissions)~~
6. ~~Failover acceptance test (drill + jailed CI test)~~
7. ~~Native delete (trash with restore) and document tools (PDF, Word, Excel)~~
8. ~~MCP federation, phase 1: MCP servers a device runs, offered through the gateway with a `device` argument~~

## Documentation

The files in `docs/` are planning documents. The filesystem and computer routes implement the roadmap's filesystem operations; the filesystem route now also offers asynchronous file and content search. The computer route covers search, commands, processes, remote devices, documents (PDF, Word, Excel) and native recoverable delete. Synchronization remains unimplemented. The documents refer to Friday (Linux) and Thanatos (Windows).

- `docs/phase-2-desktop-plan.md` plans desktop interaction. Its first step, `list_windows`, is implemented (see [Desktop and media inventory](#desktop-and-media-inventory)); the rest is not. Its phase numbers are its own and don't match the [Roadmap](#roadmap) above.
- `docs/capability-roadmap.pdf` lists the capabilities ContextBridge targets, with an implementation checklist. The checklist is a blank tracker, not a status report. It is generated by `scripts/build-roadmap-pdf.py`.
- `docs/vps-gateway.md` runs the gateway on a Linux VPS behind Cloudflare Tunnel, with agents connecting from any network without Tailscale, and migrates an existing gateway's devices and client approvals to it.
- `docs/local-health-check.md` is the on-host checklist for Friday and Thanatos: deployed revision, service and enrollment state, exposure, and crash, restart, reboot and half-open recovery tests. Its scripts are in `scripts/healthcheck/`.
- `docs/computer-use-linux-review.pdf` evaluates `agent-sh/computer-use-linux` as a Linux desktop-control engine for ContextBridge. It is generated by `scripts/build-review-pdf.py`.

Both scripts share `scripts/pdf_common.py`. To rebuild a PDF after editing its script (requires the DejaVu fonts; set `CONTEXTBRIDGE_FONT_DIR` if they are not in a standard font directory):

```sh
python3 -m pip install -e '.[docs]'
./scripts/build-roadmap-pdf.py
./scripts/build-review-pdf.py
```

## Status

No route is production-validated yet. Authentication-front/sidecar deployments and systemd services are intentionally left out.

**Upgrading an older deployment.**
- **The read-only knowledge route is gone.** It served `search` and `fetch` over a JSONL export of a retired data store. `scripts/run-contextbridge.sh`, `configs/contextbridge.yaml`, port 8790 and `MCP_AUTH_TOKEN` are no longer used; stop any service that starts the route and remove its connector from ChatGPT or Claude. `MCP_AUTH_TOKEN` is still stripped from command environments in case a host keeps it set.
- **The filesystem route moved.** If you start it with `scripts/run-contextbridge-fs.sh`, nothing changes. Otherwise start it with `python3 -m contextbridge.filesystem.gateway`. Its timeout settings are now named `CONTEXTBRIDGE_MCP_*`; the old `UGA_MCP_*` names are still read when the new one is unset.

`src/contextbridge/projects.py` (a project-to-host-to-repository registry, see `configs/projects.example.yaml`) and `src/contextbridge/task_ledger.py` (a SQLite ledger of task states) are library foundations: no route, tool, or CLI uses them yet, and neither grants any access.

## License

ContextBridge is released under the MIT License; see [`LICENSE`](LICENSE).
