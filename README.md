# ContextBridge

A self-hosted MCP gateway that gives AI assistants authenticated, policy-controlled access to approved knowledge and to your own computers. ContextBridge has no runtime dependency on Desktop Commander or any hosted relay, so it keeps working if those go away or lose their permissions.

It has two routes, each with its own server, port, and credential:

| Route | Module | Tools | Credential |
|---|---|---|---|
| Knowledge (UGA) | `uga.gateway` | `search`, `fetch` over approved JSONL records | `MCP_AUTH_TOKEN` |
| Computer | `contextbridge.computer` | files, commands, sessions, processes | `CONTEXTBRIDGE_COMPUTER_TOKEN` |

Being able to read knowledge never grants computer access. The computer route won't start if its token matches `MCP_AUTH_TOKEN`, and each route rejects the other's token.

## Installation

```sh
python3 -m pip install -e '.[dev]'
python3 -m pytest        # includes tests/test_acceptance.py, which launches both gateways over HTTP
```

ContextBridge requires FastMCP 3.x (`fastmcp>=3,<4`). It has no runtime dependency on Desktop Commander, Node, or npx, and the acceptance tests run both gateways in an environment without them.

## Knowledge route

```sh
export MCP_AUTH_TOKEN="<strong random secret provided by secret manager>"
export UGA_DATACORE_JSONL="/path/to/approved/datacore.fetch.v1.jsonl"
./scripts/run-contextbridge.sh
```

The JSONL export must contain approved records with `id`, `title`, `text`, and `url` fields. It has exactly two operations (`search` and `fetch`), default-deny tool middleware, read-only annotations, and audit logging. It binds to loopback by default.

## Computer route

The computer route is an independent replacement for Desktop Commander's local tools. The policy in `configs/computer.yaml` is enforced on the machine itself, and only the tools it permits are advertised:

| Tool | Desktop Commander equivalent | Advertised when |
|---|---|---|
| `list_directory`, `read_file`, `get_file_info`, `search_files`, `search_code`, `get_system_info` | same names / `get_config` | always (read-only) |
| `write_file`, `edit_block`, `create_directory`, `move_file` | same names | `filesystem.writable_roots` is non-empty |
| `run_command`, `start_process`, `read_process_output`, `interact_with_process`, `force_terminate`, `list_sessions` | same names (`run_command` is a one-shot convenience) | `commands.mode` is not `disabled` |
| `list_processes` | same | `processes.list: true` |
| `kill_process` | same | `processes.allow_kill: true` |

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

Three checks run on **every tool call**, at the moment it executes:

1. **Policy surface.** The tool must be one the local policy enables.
2. **Token scope.** The bearer token must carry the tool's scope: `computer:read` (file reading, search, system info, process listing), `computer:write` (file changes), `computer:execute` (commands and sessions), or `computer:process` (`kill_process`). `auth.scopes` in the config sets what the token carries. Tools outside those scopes are hidden from the tool list and refused if called anyway.
3. **Policy checks.** The engine re-validates every path, command, working directory, and limit before acting.

### Policy

- **Paths.** Every path resolves through symlinks before it is checked, so neither `..` nor a symlink can escape `filesystem.roots`. Writes are allowed only inside `filesystem.writable_roots`. Any path with a component matching a `deny` glob (`.ssh`, `.env*`, `*.pem`, `*.kdbx`, and so on) is hidden from listings and searches and refused for reads and writes. The policy file and the audit log can never be written or moved through ContextBridge.
- **Limits.** Reads, writes, search results, and search time all have caps. Rewrites are atomic and preserve file mode. `edit_block` fails unless the match count is exactly what the caller expected.
- **Commands.** `allowlist` mode runs one program per call without a shell. The program must be on the allowlist, and pipes, redirects, `;` and `&&` are refused before anything runs. `unrestricted` mode runs through `bash -c`. The working directory must be inside a readable root. Every command has a hard timeout (`max_timeout_seconds` caps whatever the caller asks for), and a timed-out command is killed along with every process it started. Output is capped in memory, keeping the head and the tail. Variables that look like credentials (`*TOKEN*`, `*SECRET*`, `*PASSWORD*`, …) are removed from the child's environment, and both gateway tokens are always removed.
- **Sessions.** `start_process` runs long or interactive programs in the background. Concurrent sessions are capped (`max_sessions`) and each is killed when it reaches `max_session_seconds`.

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

A `service_started` event records the policy and tool surface at startup. The audit log fails closed: if the `requested` or `started` event can't be written, the operation does not run. File content and stdin are logged only as a size and a hash, never the text.

## Remote access

Neither route includes an OAuth server or a public HTTPS listener, and neither depends on Authentik. The knowledge route binds to loopback by default. The computer route refuses any non-loopback address; there is no override. Remote-device connectivity is Phase 3 and isn't implemented yet. Do not forward ports 8790 or 8791 to the internet.

## Roadmap

1. ~~Independent local filesystem and terminal tools~~
2. ~~Local policy enforcement, execution limits, tests~~
3. Remote agent transport and device registration (outbound agent connections, heartbeats, revocation)
4. Windows agent for Thanatos (the engine is written cross-platform but is only tested on Linux so far)
5. Authenticated remote MCP endpoint for ChatGPT and Claude (OAuth front end, per-device permissions)
6. Failover acceptance test with Desktop Commander fully stopped

## Status

The knowledge route is a standalone extraction from an archived UGA implementation. Authentication-front/sidecar deployments and systemd services were intentionally left out. Neither route is production-validated yet.
