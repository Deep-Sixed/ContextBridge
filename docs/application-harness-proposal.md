# Proposal: application harnesses on ContextBridge (design only, nothing implemented)

Status: draft for review. Based on a read of `computer/commands.py`, `computer/policy.py`,
`computer/scopes.py`, `computer/federation.py`, `configs/computer.yaml`, `oauth/provider.py` and the README
federation section. CLI-Anything findings (registry/installer, licence) are from an external source review and
were not re-verified here. No harness was installed or run.

## 1. Findings that shape the design

1. **The command allowlist is program-level only.** `ComputerPolicy._allowlisted_argv` checks `argv[0]` against
   `commands.allow` and passes every other argument through. There is no argument, subcommand or flag filtering.
   `computer.yaml` and `allowlist_warnings()` say so explicitly. `git`, `make`, `find`, `awk`, `ssh`, `env`,
   `xargs` and similar are classed as program runners and warned about. Allowlisting a harness entry point would
   therefore expose its whole command set, and any harness with an "exec" or script-file operation is equivalent
   to unrestricted mode. The challenge to "allowlist entry per harness" is correct.
2. **Allowlisted commands bypass the filesystem deny list.** The config comment states commands run with the OS
   user's full permissions and are not subject to the deny list. A harness `--output ~/.ssh/...` is not stopped.
3. **MCP federation already exists and is the right seam.** `mcp_servers` in a device's own config starts stdio MCP
   servers, lists their tools, and offers them as `<server>_<tool>` with: a per-server `scope`, per-tool
   `tool_scopes`, an optional `tools:` allowlist of the server's own tool names, a credential-stripped
   environment, and `requested → started → completed` audit (arguments logged as size and hash). Only the
   machine's own config can add a server; the gateway cannot start programs. This already carries
   operation-level control, enforced per tool.
4. **Scopes are a closed set** (`ALL_SCOPES`: `computer:read|write|execute|process`, `desktop:observe`,
   `media:discover`). `tool_scopes` values must come from it, and the OAuth consent page lists those six. New
   scopes mean changes in `scopes.py`, `oauth/provider.py` (`SCOPE_DESCRIPTIONS`, consent form, grant store) and
   any device-grant checks.
5. **`desktop.py` is only a window inventory.** Agent-Desktop is expected to arrive via federation (the README
   and `computer.yaml` examples use `agent-desktop mcp`), so it needs no new engine.

## 2. Ownership boundary (revised)

ContextBridge makes computers accessible to agents. OmniLink connects, manages and orchestrates agents and their
available capabilities. Applied to this proposal:

| Concern | Owner |
|---|---|
| Harness execution, manifest validation, argument/path validation | ContextBridge (host side) |
| Local discovery of installed harnesses and their health | ContextBridge (host side) |
| Host-level security: path policy, deny list, hash pinning, credential-stripped env, audit | ContextBridge |
| Centralised MCP federation, aggregation, cross-device capability routing | OmniLink |
| Fleet-wide deployment, installation and orchestration | OmniLink |
| Agent-Desktop and CLI-Anything | Independent integrations, maintained upstream; neither is forked nor vendored |

ContextBridge's existing `mcp_servers` federation stays as is, for compatibility and standalone operation, until the
transition to OmniLink is validated. It is in production, so nothing here removes or changes it. This split is an
architectural recommendation from the discussion. It has not been checked against OmniLink's source, and the
OmniLink-side items below are assumptions to confirm.

Consequence for the design: the harness adapter must **not depend on any particular federator**. It is a plain stdio
MCP server that ContextBridge's federation can start today and that OmniLink can consume later. Everything that
makes it safe is enforced **inside the adapter and the host agent**, so a federator in front of it can route calls
but is never the only control.

## 3. Principles

- Compatibility with CLI-Anything, no dependency on it or its registry client; no fork.
- Reuse the host's existing execution, path policy, grants and audit. No new execution engine.
- The adapter is federator-neutral. Host-side enforcement cannot be bypassed by whoever routes the call.
- Installation is separate from execution permission. Installing never happens through an assistant.
- Registry-neutral: CLI-Hub is one possible source among others.
- Fleet-wide deployment and orchestration are OmniLink's, not ContextBridge's.
- Default-deny at operation level: an operation not in the manifest does not exist.

## 4. Operation-level restriction: options

| Option | How | Verdict |
|---|---|---|
| A. Allowlist the harness binary | Existing `commands.allow` | Rejected. All-or-nothing; fails finding 1. |
| B. Argument-pattern allowlist in `commands.allow` | New matching rules on argv | Possible but fragile. Needs per-program option parsing (`git -c`, `--exec`); large new attack surface in the central policy code. |
| C. Manifest-driven adapter exposed as a stdio MCP server | Each declared operation is one MCP tool with typed parameters and a fixed argv template; no shell. Consumed by ContextBridge's existing federation today, by OmniLink later. | **Recommended.** Undeclared operations are unreachable by construction, and enforcement does not depend on the consumer. |
| D. Run upstream harness MCP/CLI directly | Federation `command:` pointing at a harness | Acceptable only if the harness exposes narrow tools and the `tools:` allowlist is used; otherwise same exposure as A. |

## 5. Registry-neutral harness manifest (draft)

One manifest per harness, written or reviewed by the operator, stored on the device (e.g. `harnesses/<id>.yaml`),
never fetched at call time from a registry.

```yaml
id: libreoffice                    # lowercase, matches federation server-name rules
manifest_version: 1
provenance:                        # recorded, not trusted
  source: cli-anything             # free-form: cli-anything | public-cli | first-party | ...
  package: cli-anything-libreoffice
  version: "0.0.0"                 # exact, pinned
  artifact_sha256: "<hash of installed wheel/binary>"
  licence: Apache-2.0
entrypoint: /opt/harnesses/libreoffice/bin/cli-anything-libreoffice   # absolute path; no PATH lookup
requires: {app: libreoffice, min_app_version: "7.6"}
output: json                       # adapter always appends the harness's JSON flag; non-JSON output is an error
operations:
  - name: doc_info
    class: read                    # read | write | destructive | remote-write | admin
    argv: ["doc", "info", "{path}"]
    params:
      path: {type: path, access: read}      # resolved through ComputerPolicy.resolve; deny list applies
    timeout_seconds: 30
  - name: export_pdf
    class: write
    argv: ["export", "pdf", "{src}", "{dest}"]
    params:
      src:  {type: path, access: read}
      dest: {type: path, access: write}     # must be in a writable root
skill:
  file: SKILL.md
  sha256: "<hash>"                 # exposed only if the hash matches
```

Rules: typed params only (`path`, `enum`, bounded `int`/`float`, `string` with regex and length cap); a value
starting with `-` is rejected unless the type is an enum; argv is built from the template, never concatenated
into a shell; every `path` param goes through the existing policy (resolution, symlink handling, deny list,
writable-root check); an operation whose upstream command can run scripts or arbitrary subcommands is not
declarable (`class: admin` requires an explicit operator opt-in and its own scope).

Class → scope mapping with **no new scopes at first**: `read` → `computer:read`, `write` → `computer:write`,
`destructive`, `remote-write`, `admin` → `computer:execute`. Today per-operation scoping reuses federation's
`tool_scopes`. Because a different federator may route calls later, the adapter also publishes each tool's class
and required scope in its own tool metadata, and the host agent re-checks the device grant for that scope on every
call. Scope enforcement then no longer lives only in whichever layer routes the call.
A later step could add per-application scopes (`app:<id>:<class>`), which needs the consent-UI changes in
finding 4 and is worth doing only if one grant per application proves necessary.

## 6. Per-device capability discovery

Local discovery is ContextBridge's. Cross-device aggregation of what each device offers is OmniLink's.

- The adapter (one server per device, or one per harness) reports its tools as a normal MCP tool list. Under
  today's federation, `list_devices` shows them as `mcp_tools`; OmniLink can read the same list over the same MCP
  interface. Discovery of "which harnesses are installed and healthy" is the tool list itself, with no new
  protocol and no ContextBridge-specific wire format.
- Add a read-only `harness_inventory` tool to the adapter: per manifest, id, pinned version, whether the
  entrypoint exists and its hash matches `artifact_sha256`, whether the backing app is present, and operation
  names by class. A mismatch makes the harness's tools disappear instead of failing at call time.
- No auto-discovery from PATH, no registry queries from the device at runtime.

## 7. Exposing SKILL.md safely

SKILL.md is third-party text delivered to an assistant, so it is a prompt-injection channel. Proposed handling:

- Serve it only as the adapter's own data (a `harness_skill` tool returning text), only when the file hash equals
  the manifest hash, with a size cap, and wrapped with a fixed header stating it is untrusted reference text that
  cannot widen permissions.
- Do not rely on MCP `resources`/`prompts`: the filesystem route default-denies both; I have not confirmed the
  computer route's behaviour and would check before depending on them.
- The authoritative description of operations given to the assistant is generated from the manifest (names,
  parameter schemas, class), not from SKILL.md. SKILL.md is optional background.

## 8. Installation, kept separate

- Harnesses are installed by the operator, outside ContextBridge, into a dedicated location (venv per harness,
  pinned version and hash). No ContextBridge tool installs or updates software.
- Reasons (from the external review, to be re-verified before relying on them): CLI-Hub executes
  registry-supplied commands with `shell=True`, has no signature verification, and uses unpinned `@latest` for
  npm. A remotely reachable assistant must never trigger that, particularly on a host with passwordless sudo.
- Updating a harness means re-reviewing the manifest and updating the pinned hash. The upstream stays
  independently updateable because ContextBridge only reads manifests, and any version bump is an explicit,
  reviewed change.
- Licence: repo Apache-2.0 vs CLI-Hub `setup.py` MIT is unresolved. The design copies no upstream code (it reads
  `--help`/SKILL.md as reference and runs installed binaries), which sidesteps it for now. Resolve before any
  vendoring.

## 9. Minimal proof of concept

Goal: one read-only operation end to end, to test the seam rather than the catalog.

1. Pick one installed CLI-Anything harness with a read-only `--json` operation on a document file. Choose after
   running its `--help` on a test machine; I have not run any harness, so the command names above are
   illustrative.
2. Hand-write its manifest with a single `read` operation and one `path` param.
3. Write a small stdio MCP adapter (new module, e.g. `contextbridge.harness`) that loads manifests, registers one
   tool per operation, validates params, resolves paths through `ComputerPolicy`, runs the argv with
   `child_env()`, timeout and bounded output (reuse `run_command` internals rather than a new runner), and fails
   closed on any unknown operation or non-JSON output.
4. Register it in the existing `mcp_servers` with `scope: computer:read` and a pinned command (standalone/compat path). Also confirm the same adapter can be consumed unchanged by an MCP client other than ContextBridge's federation, which stands in for OmniLink.
5. Acceptance tests (pytest, matching the repo's style): undeclared operation unreachable; `-`-prefixed and
   `..`/symlink/deny-listed paths rejected; write path outside writable roots rejected; hash mismatch removes
   tools; output over cap truncated; call audited as `requested → started → completed`; token without
   `computer:read` refused.

## 10. Required changes (not implemented)

| Area | Change | Size |
|---|---|---|
| New module | Manifest loader, validator, adapter MCP server, inventory/skill tools | medium |
| `policy.py` | Expose a reusable "resolve path for read/write" entry point for the adapter (likely already `resolve`) | small |
| `commands.py` | Possibly factor the bounded-run core out of `run_command` for reuse | small |
| `computer.yaml` / README | Document `harnesses:` location and the federation entry; warn against allowlisting harness binaries | small |
| `scopes.py`, `oauth/provider.py` | None for the PoC; per-app scopes later | deferred |
| Tests | As in section 9 | medium |
| Out of scope | Installer, registry client, fleet rollout (OmniLink), Agent-Desktop (independent integration), centralised federation and cross-device routing (OmniLink); existing `mcp_servers` federation is left unchanged | n/a |

## 11. Open questions

0. OmniLink-side assumptions (not verified against its source): it consumes stdio/MCP tool lists and tool metadata, and
   it will route calls to host agents that still enforce grants. Confirm both before the transition.

1. Are per-class scopes enough, or do you want per-application consent (e.g. LibreOffice yes, Git no)?
2. Should destructive and remote-write operations require a per-call approval step beyond scope? Today the
   consent model is per grant, not per call.
3. How are manifests authored: by hand per harness, or generated from `--help` and then reviewed? Generation is
   itself LLM-shaped risk and should output a draft that a human approves.
4. Confirm the computer route's handling of MCP resources/prompts before choosing any SKILL.md transport other
   than a tool.
5. Licence question for any future reuse of CLI-Anything code.
