# ContextBridge: bidirectional private computer control

**Target:** ContextBridge replaces Desktop Commander Remote for Friday (Linux),
Thanatos (Windows), and Jarvis (Linux). The product is **not** a unidirectional
or read-only appliance. Read-only Datacore search/fetch is only one isolated
capability. This document is an implementation contract, not a claim that all
phases are already deployed.

## Non-negotiable requirements

1. **Tailscale required** for all remote transport. No public TCP listener,
   public relay, or fallback around the tailnet. Bind host services to
   tailscale interfaces or loopback with deliberate proxies. Enforce tailnet
   ACL/grants between gateway and enrolled host devices. Never treat a
   `100.64.0.0/10` address as proof of device identity.
2. **Active host connector required** on each Linux/Windows target. Agent
   persists as a systemd service on Linux or supervised service/task on Windows;
   must connect outbound or accept tailnet-only transport, reconnect with
   bounded exponential backoff, and advertise a heartbeat and capabilities.
3. **Bidirectional protocol**: gateway-to-agent requests; agent-to-gateway
   typed results, errors, progress, bounded stdout/stderr, heartbeat and event
   notifications. Neither side may treat network send as completed execution.
4. **Mutual identity**: explicit enrollment and revocation, per-device
   asymmetric key authentication in addition to tailnet controls; bind
   enrolled key to a stable Tailscale node identity, not host display name
   or IP alone. Support key rotation and deny ambiguous identities.
5. **Local policy always authoritative**: each agent enforces per-operation
   tools, allowed roots, path resolution, command/program allowlist, working
   directory, CPU/time/output caps, and OS-specific sandboxing. Gateway policy
   cannot override local denials.
6. **No automatic cross-host synchronization**: file transfer and sync are
   explicit, scoped operations with size/hash validation, dry-run for
   destructive sync, conflict handling and atomic apply where possible.
7. **Durable lifecycle semantics**: request ID and attempt ID, acknowledgement,
   accepted, started, finished with exit status, canceled and disconnected
   states are distinct. No automatic retry of a non-idempotent write/command
   after uncertain completion. Deduplication and bounded retention required.
8. **Fail closed** on disconnected tailnet, unknown device, invalid signature,
   unsupported capability or inaccessible policy. Protect tokens in OS secret
   storage; never log command arguments/secrets by default.
9. **Auditing**: central and host-local audit, request correlation, explicit
   `audit_write_failed` state; privileged mutating operations require an
   enforceable durability policy before production deployment.
10. **GUI computer use** is an optional capability running under an authorized
    interactive user session with consent and visible control; it must not
    silently inherit root/system privileges.

## Logical layout

```text
ChatGPT / Claude / OpenCode
             |
   MCP auth + gateway policy
             |
   ContextBridge Gateway (Friday)
     |       |           |
  knowledge  devices    audit
  search/    router     events
  fetch      |
             +---- Tailscale tailnet (mandatory) ----+
             |                 |                      |
        Friday agent     Thanatos agent          Jarvis agent
           Linux            Windows                Linux
        host policy        host policy            host policy
        + audit            + audit                + audit
```

The gateway may use a reverse, authenticated WebSocket session initiated by
an agent over Tailscale. This is still bidirectional at the application layer:
requests travel gateway -> agent, results and events agent -> gateway.
Do not conflate transport direction with authorization direction.

## Incremental delivery plan and existing PR ownership

| Stage | Existing work | Completion gate |
| --- | --- | --- |
| A. Knowledge isolation | `main`, PR #6 | Authenticated bounded search/fetch; never gain host tools |
| B. Filesystem | PR #7 | No symlink/hardlink traversal escapes; timeouts have explicit uncertain completion; host-local policy |
| C. Agent + bidirectional sessions | PR #1 | Device enrollment, auth, secure multiplexing, reconnect and replay safety |
| D. Tailnet admission | This PR; integrate with PR #1 | Peer node ID and device public key checked for **every** connection; denied off tailnet |
| E. Host production checks | not yet proven | Friday, Thanatos and Jarvis each pass tests with Desktop Commander disabled |
| F. GUI | separate follow-up | Interactive session policies and consent validated |

`src/uga/tailnet.py` is a **pure identity-validation helper**. It does not
change the network stack or enforce access by itself. The remote listener in
PR #1 must call it during connection admission after obtaining fresh trusted
`tailscale status --json` locally. Never trust status JSON provided by
the connecting agent, and do not use forwarded HTTP headers for peer IP
without an authenticated trusted proxy.

## Integration acceptance tests

- Unknown node in an otherwise valid tailnet: denied.
- Known node with wrong enrolled agent key: denied.
- Correct agent key from a different tailnet node: denied.
- Tailscale down/disconnected: all remote control denied; local access remains separately authorized.
- Reconnect during an executing command: operation outcome marked unknown
  until reconciled; no blind mutation replay.
- Policy denial on agent: gateway cannot override.
- File escape via symlink rename races, hard links and Windows junctions:
  denied under concurrent adversarial test.
- Host restart: agent service reconnects automatically with bounded backoff.
- Terminal output and file transfer enforce quotas under adversarial workloads.
- Bidirectional event/result streaming verified on actual Linux and Windows hosts.
- With Desktop Commander disabled, full read/write/command/process capability
  and re-enrollment/revocation tests pass on all three hosts.

## Boundaries

ContextBridge is a standalone computer-control product and service. It owns its
MCP gateway, agent runtimes, enrollment, configuration, policy, audit logging,
release process, and system services. Its build, startup, tests, and operation
must have **no dependency on any external AI router, inference gateway, coding
harness, or knowledge system**. The agent protocol and API are usable by any
authorized MCP client; clients are integrations, not runtime dependencies.

Existing read-only Datacore behavior remains an optional, isolated capability.
Core file, process, terminal, network, and desktop-control operations must not
require Datacore or any knowledge export to be present.

**Never merge the broad remote-agent PR solely on a green unit-test run.**
Review and merge in independently testable security and transport stages.
