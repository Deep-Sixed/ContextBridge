# Phase 1 — Working Computer Bridge (implementation plan)

Status: **in progress**. ContextBridge is a standalone product; neither AI inference nor task routing is part of its runtime.

## Phase 1 definition of done

A compatible MCP client can connect to the ContextBridge gateway, enumerate permitted enrolled hosts, inspect bounded host information, read an approved file, run a narrowly allowed command, observe its verified result, and perform an explicitly permitted write. The same workflow works on Friday (Linux) and Thanatos (Windows) through mandatory Tailscale with active agents. Jarvis joins once online. Disconnects cannot silently repeat commands or writes. Desktop Commander remains installed until the independent workflow is demonstrated.

## Existing code ownership

- **PR #1** (`claude/determined-thompson-2vwa8k`): full computer engine, WSS remote hub/agent, Ed25519 enrollment, audit, Linux/Windows policy and service scripts. This is the **implementation base** for Phase 1, not a finished deployment.
- **PR #8** (`feature/tailscale-bidirectional-contract`): pure tailnet identity validation and the bidirectional architecture contract. **Integrate its guard into PR #1's `AgentHub._handle`** before serving enrollment or authentication.
- **PR #7**: alternate filesystem-only MCP server. Do **not** merge it independently into production next to PR #1 until the duplicate filesystem surfaces are reconciled. Prefer PR #1's policy-enforced computer engine after a security review, or explicitly replace it; avoid two competing writers.
- **PR #6**: optional Datacore-specific gateway protections. Important for that route, but **not a prerequisite for host control**.

## Ordered engineering changes

1. **Establish a single canonical computer API.** Document one MCP endpoint, a stable device-qualified command/file/tool naming contract, and local versus remote authority. PR #1 currently uses `serve.port=8791`; PR #7 also proposes port 8791. Resolve port and tool overlap before merging.
2. **Mandatory tailnet admission.** Agent listener must reject endpoints outside trusted, locally observed Tailscale peers, then enforce enrolled Ed25519 identity bound to the stable node ID. Validate both fresh enrollment and reconnect. Use Tailscale IP/interface only; no permissive LAN address fallback.
3. **Remove public exposure from default config.** PR #1's sample instructs `tailscale funnel` (public). This contradicts Tailscale-only deployment. Use private tailnet access and an explicitly supported MCP client access method; whether particular hosted clients can reach a private tailnet must be validated separately. Never enable Funnel as a default.
4. **Harden mutating operations.** Resolve symlink races and Windows reparse points, use bounded process execution, defend against command-allowlist bypasses, and distinguish accepted/started/completed/succeeded in durable audits. Lost replies must leave outcomes unknown until reconciled.
5. **Install isolated agent identity/configuration.** No keys committed to Git. Create least-privilege host service configs and explicit read/write/command scopes. Agents reconnect automatically; privilege escalation requires consent.
6. **Cross-host smoke tests.** Friday to Thanatos over the tailnet: authenticated enrollment, device discovery, read, allowlisted command, approved write, disconnect/reconnect, denial, revocation and evidence. Repeat on Friday local agent and Jarvis when available.
7. **Cutover only after proof.** Keep Desktop Commander running during comparison. Disable it only in a controlled acceptance test, then restore it if any capability fails.

## Known gaps observed October 8, 2026

- `src/contextbridge/remote/hub.py` from PR #1 accepts peer IP at the WebSocket handler but does **not** yet call PR #8's Tailscale node validator.
- `configs/computer.yaml` has `agents.enabled: false`; agents are **not deployed** by merging alone.
- PR #1 sample remote access includes a public `tailscale funnel` example, contrary to the private-only goal.
- PR #7 and PR #1 both target TCP port 8791 through separate filesystem/computer servers.
- The current PR #8 branch passed its tests on Friday; host-agent tests and real-world cutover remain outstanding.

## Release gates

- **P1-A**: integrated code passes Linux and Windows CI, tests for untrusted tailnet peers and device-key mismatches.
- **P1-B**: Friday local authenticated gateway plus active agent operates without an external AI router or knowledge export.
- **P1-C**: Thanatos connects over Tailscale; signed requests and authorized results verified end-to-end.
- **P1-D**: Jarvis added; disconnect/reconnect, revocation, audit durability and mutating-operation reconciliation verified.
- **P1-E**: Desktop Commander-disabled acceptance suite completes with rollback confirmed.

## Safeguards

No automatic public exposure, unrestricted shell, background camera or microphone, password retrieval, system-wide network reconfiguration, or removal of the existing remote tool. Start with least-privilege read capabilities; explicit writable roots and commands are opt-in.
