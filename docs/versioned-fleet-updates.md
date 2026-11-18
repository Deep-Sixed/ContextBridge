# Versioned fleet updates — design and acceptance requirements

**Status: draft, not deployable.** The existing `contextbridge-update-fleet`
continues its in-place updates. The path planner in this PR is deliberately
not wired to running services until the transaction and recovery tests pass.

## Goal

Keep each agent checkout and Python environment in an immutable
`<version_root>/version/<full-git-sha>` folder and make the installed
service/task point to the new folder. Preserve the previous folder as a
rollback target. Update the root-owned fleet registry only **after**
reconnection and health verification.

Examples:

| Device | Version root | Current migration source |
|---|---|---|
| friday | `/home/jarvis/omnilink` | `/home/jarvis/omnilink/version/accd8d7` |
| thanatos | `C:/Omnilink` | `C:/Omnilink/version/accd8d7` |
| p70 | `C:/Omnilink` | `C:/ContextBridge` |

The gateway checkout stays at `/opt/contextbridge/app` initially:
changing it risks losing the updater mid-operation. Its local agent's
venv also remains in place for this first phase.

## Mandatory implementation sequence

1. Resolve the target to a **full commit SHA**, verify it is descended
   from current HEAD, validate the `version_root`, and check free space.
2. Fetch/clone the target to a **new** version directory without overwriting
   the old directory. Detect dirty tracked files, symlinks/junctions and
   preexisting destinations before making changes.
3. Build the target venv and install the package before touching the running
   service/task. Windows dependency changes are allowed only if installation
   is in a separate venv; never install into the running venv.
4. Validate the package, policy, enrollment identity and configuration
   paths from the *actual running unit/task*; do **not** assume
   `configs/agent.yaml` on P70 (observed `agent.local.yaml`).
   Preserve task triggers, account and run level, and systemd user-unit
   properties; back up the original definition.
5. Atomically switch the service/task to the new executable. Use a
   separately hosted delayed restart, so the agent does not terminate its
   own command midway through the switch.
6. Verify the newly connected agent reports the target version and that
   the service/task remains healthy. On failure, restore the previous
   definition, restart it and confirm rollback reconnects.
7. Only after success, update `fleet.yaml` using a root-only temporary
   file, atomic replace and retained backup; preserve permissions and
   all other device entries. Future updater invocations must not target
   stale paths.
8. Retain the last working directory; do not delete old checkouts or
   environment folders automatically. Document manual rollback.

## Dry run

`--dry-run` must show the source, target, service/task, config and
identity paths, planned steps, and rollback directory, without changing
the remote filesystem, services or `fleet.yaml`.

## Tests required before ready for review

- Linux systemd user unit switch, delayed restart, and reconnect.
- Windows scheduled task switch, preserving triggers, principal, run level,
  repetition and actual config path.
- P70 migration from `C:/ContextBridge` to `C:/Omnilink/version/<sha>`.
- Dependency changes installed into an unused venv on Windows.
- Failures at checkout, install, switch, restart, reconnect and fleet YAML
  commit restore the prior runnable agent.
- Interrupted update recovery and idempotent second run.
- Dirty trees, invalid SHAs, path traversal, existing target and insufficient
  disk space fail closed.
- `fleet.yaml` updates remain root-only and make no modifications during dry run.
- Gateway remains reachable and all four agents are online after a real
  opt-in smoke test; no smoke test against production before review.

## Compatibility

Keep the default in-place mode unchanged for existing fleet files.
Introduce versioned mode only behind a **per-device explicit configuration
field**, rather than silently inferring it from folder names.
