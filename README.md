# ContextBridge

A self-hosted MCP gateway that gives AI assistants authenticated, policy-controlled access to approved knowledge and to your own computers. ContextBridge has no runtime dependency on Desktop Commander or any hosted relay, so it keeps working if those go away or lose their permissions.

It has two routes, each with its own server, port, and credential:

| Route | Module | Tools | Credential |
|---|---|---|---|
| Knowledge (UGA) | `uga.gateway` | `search`, `fetch` over approved JSONL records | `MCP_AUTH_TOKEN` |
| Computer | `contextbridge.computer` | files, commands, sessions, processes | `CONTEXTBRIDGE_COMPUTER_TOKEN` |

Being able to read knowledge never grants computer access. The computer route won't start if its token matches `MCP_AUTH_TOKEN`.

## Installation

```sh
python3 -m pip install -e '.[dev]'
python3 -m pytest
```

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

Over HTTP, for remote clients behind your own TLS/OAuth front end:

```sh
export CONTEXTBRIDGE_COMPUTER_TOKEN="<different strong secret>"
./scripts/run-computer.sh                 # serves http://127.0.0.1:8791/mcp
```

Over stdio, for a local MCP client such as Claude Desktop, OpenCode, or Claude Code. The client starts the process itself, so no token is needed:

```json
{
  "mcpServers": {
    "contextbridge": {
      "command": "/home/you/ContextBridge/scripts/run-computer.sh",
      "args": ["--transport", "stdio"]
    }
  }
}
```

### Policy

- **Paths.** Every path resolves through symlinks before it is checked, so a link can't escape `filesystem.roots`. Writes are allowed only inside `filesystem.writable_roots`. Any path with a component matching a `deny` glob (`.ssh`, `.env*`, `*.pem`, `*.kdbx`, and so on) is hidden from listings and searches and refused for reads and writes. The policy file and the audit log can never be written through ContextBridge.
- **Limits.** Reads, writes, search results, and search time all have caps. Rewrites are atomic and preserve file mode. `edit_block` fails unless the match count is exactly what the caller expected.
- **Commands.** `allowlist` mode runs one program per call without a shell. The program must be on the allowlist, and pipes, redirects, `;` and `&&` are refused. `unrestricted` mode runs through `bash -c` (or PowerShell on Windows). The working directory must be inside a readable root. Every command has a hard timeout, and a timed-out command is killed along with every process it started. Output is capped (head and tail are kept). Variables that look like credentials (`*TOKEN*`, `*SECRET*`, `*PASSWORD*`, …) are removed from the child's environment, and both gateway tokens are always removed.
- **Sessions.** `start_process` runs long or interactive programs in the background. Concurrent sessions are capped (`max_sessions`) and each is killed when it reaches `max_session_seconds`.
- **Audit.** Every call is written to the audit log as a JSONL line with the tool, the paths and commands, the outcome, the exit code, and the client. For file content and stdin, only the size and a hash are logged, never the text.

**Know the boundary.** The command allowlist controls *which programs* run, not *what they touch*. `git diff --no-index` can read any file the OS user can, for example, and allowing a shell or an interpreter makes allowlist mode equivalent to unrestricted. The filesystem deny list applies to the file tools, not to commands. For a hard boundary, run the computer route as a dedicated OS user that can only reach what you intend to share.

## Remote access

Neither route includes an OAuth server or a public HTTPS listener. Both bind to loopback, and the computer route refuses any other address unless `serve.allow_non_loopback: true` is set. To reach them from ChatGPT or Claude on the web, put them behind a separate authenticated TLS/OAuth front end. Do not forward ports 8790 or 8791 directly to the internet.

## Roadmap

1. ~~Independent local filesystem and terminal tools~~
2. ~~Local policy enforcement, execution limits, tests~~
3. Remote agent transport and device registration (outbound agent connections, heartbeats, revocation)
4. Windows agent for Thanatos (the engine is written cross-platform but is only tested on Linux so far)
5. Authenticated remote MCP endpoint for ChatGPT and Claude (OAuth front end, per-device permissions)
6. Failover acceptance test with Desktop Commander fully stopped

## Status

The knowledge route is a standalone extraction from an archived UGA implementation. Authentication-front/sidecar deployments and systemd services were intentionally left out. Neither route is production-validated yet.
