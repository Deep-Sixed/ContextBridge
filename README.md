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
python3 -m pip install -e '.[test]'
python3 -m pytest        # includes acceptance tests that launch the gateways and an agent as real processes
```

ContextBridge requires FastMCP 3.x (`fastmcp>=3,<4`). It has no runtime dependency on Desktop Commander, Node, or npx, and the acceptance tests run both gateways in an environment without them.

## Knowledge route

**Security model:** exactly two operations (`search` and `fetch`), default-deny tool middleware, read-only annotations, audit logging, and a static bearer token (at least 32 characters) required at startup. Error details are masked from clients, and only allowlisted record fields are served. It binds only to the loopback interface by default.

```sh
export MCP_AUTH_TOKEN="<strong random secret provided by secret manager>"
export UGA_DATACORE_JSONL="/path/to/approved/datacore.fetch.v1.jsonl"
./scripts/run-contextbridge.sh
```

`MCP_AUTH_TOKEN` must be at least 32 characters (for example `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`).

The data export is required: set `UGA_DATACORE_JSONL`, or `datacore_jsonl` in the config file (a relative path is resolved against the config file's directory). The environment variable wins. The export is loaded and validated at startup, and the gateway refuses to start if it is missing or invalid.

### Data format

Each JSONL line is one approved record with `id` (a non-empty string or integer), `title`, `text`, and `url`, plus an optional `metadata` object. Of the other top-level keys, only the approved fields listed in `_OPTIONAL_TOP_LEVEL_FIELDS` in `src/uga/adapter.py` are kept; any other key is dropped at load time and is never served or searched. Search matches field values, not JSON key names.

### Audit log

Every request is written as one JSON line to stderr and, if `UGA_AUDIT_LOG` (or `serve.audit_log` in the config) is set, to that file, which is created with mode `0600`. A tool call produces two lines (one from the policy middleware, one from the tool) that share a `request_id`. Rejected HTTP requests are logged as `tool: "auth"` with `missing_token` or `invalid_token`. Queries are recorded as a hash and length only; set `UGA_AUDIT_LOG_QUERY_TEXT=1` to also log the first 80 characters.

## Computer route

The computer route is an independent replacement for Desktop Commander's tools, including its remote-machine support. Every tool takes a `device` argument: `local` (the gateway's own machine, the default) or the name of an enrolled remote device (see [Remote devices](#remote-devices)). `list_devices` shows what is reachable. A tool is offered only when some device's policy enables it:

| Tool | Desktop Commander equivalent | Enabled on a device when |
|---|---|---|
| `list_directory`, `read_file`, `get_file_info`, `search_files`, `search_code`, `get_system_info` | same names / `get_config` | always (read-only) |
| `write_file`, `edit_block`, `create_directory`, `move_file` | same names | `filesystem.writable_roots` is non-empty |
| `run_command`, `start_process`, `read_process_output`, `interact_with_process`, `force_terminate`, `list_sessions` | same names (`run_command` is a one-shot convenience) | `commands.mode` is not `disabled` |
| `list_processes` | same | `processes.list: true` |
| `kill_process` | same | `processes.allow_kill: true` |
| `list_devices` | remote device list | always |

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
2. **Device.** The device must exist and be online. Its policy must enable the tool. A remote device must also have been granted the tool's scope when it was paired.
3. **Policy checks.** The device's engine re-validates every path, command, working directory, and limit before acting. For a remote device, that's the agent on that machine, under its own policy.

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
- **Liveness.** Agents send heartbeats. A device that misses three is dropped and shown offline, and its pending calls fail. Agents reconnect with exponential backoff and stop permanently once revoked.
- **Revocation.** `revoke` marks the device in the registry. The gateway refuses the next call to it and drops its live connection within a second.
- **Secrets stay hidden.** The local device can never read the TLS private key or the device registry, and an agent can never read its own identity file.
- **Audit on both sides.**
  - **Shared request ids.** A remote call carries the same `request_id` in the gateway's audit log and the agent's.
  - **Gateway events.** The gateway's log also records `device_enrolled`, `device_connected`, `device_disconnected`, `device_auth_failed`, `device_revoked`, and `device_heartbeat_lost`.
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
- **Either way:** the task restarts the agent if it exits.
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

## Network exposure

Neither route includes an OAuth server or a public HTTPS listener, and neither depends on Authentik.
- **Knowledge route:** binds to loopback by default.
- **Computer MCP endpoint:** refuses any non-loopback address; there is no override.
- **Agent listener:** the only network-facing piece. It is TLS-only, limited to private addresses, and accepts only enrolled devices.

Do not forward ports 8790, 8791, or 8792 to the internet.

## Roadmap

1. ~~Independent local filesystem and terminal tools~~
2. ~~Local policy enforcement, execution limits, tests~~
3. ~~Remote agent transport and device registration (outbound agent connections, heartbeats, revocation)~~
4. ~~Windows agent for Thanatos (native agent, job-object process trees, scheduled-task install, Windows CI)~~
5. Authenticated remote MCP endpoint for ChatGPT and Claude (OAuth front end, per-device permissions)
6. Failover acceptance test with Desktop Commander fully stopped

## Documentation

`docs/desktop-commander-inventory.pdf` lists the Desktop Commander functionality ContextBridge targets, with an implementation checklist. To rebuild it after editing `scripts/build-inventory-pdf.py` (requires the DejaVu fonts):

```sh
python3 -m pip install -e '.[docs]'
./scripts/build-inventory-pdf.py
```

## Status

The knowledge route is a standalone extraction from an archived UGA implementation. Authentication-front/sidecar deployments and systemd services were intentionally left out. Neither route is production-validated yet.
