# Phase 2 — Desktop interaction

ContextBridge remains a transport and enforcement layer. AI clients may request explicitly authorized desktop capabilities; the host agent executes and audits them.

## Phase 2a (this PR): window inventory foundation

- Add `contextbridge.computer.desktop.list_windows(authorized=False)`.
- Deny by default. The host must opt in before invoking discovery.
- Read only bounded window titles and IDs; no screenshots, keystrokes, clipboard access, focus changes, camera, or microphone.
- Windows uses visible top-level window enumeration; Linux currently supports `wmctrl -l` when a graphical session is available. Headless machines fail closed.
- The module is exposed as an audited `list_windows` MCP/engine tool only when the host enables `desktop.observe: true` **and** the client is granted `desktop:observe`. This does not grant screenshots or input.

## Delivery milestones

1. Host-policy permission `desktop:observe`; include window inventory in the audited engine and MCP surface. **Implemented in this branch.**
2. OS-aware session discovery: Windows interactive desktop vs service session; Linux Wayland/X11 with explicit user-session authorization.
3. Screen capture with permission controls, bounded data size and no unattended capture by default.
4. Input interaction (`desktop:act`) separately authorized for cursor/keyboard and window controls, requiring an interactive session.
5. Per-request approval, sensitive-window redaction, human interruption, auditable operations, and cross-host acceptance tests.

Do not interpret the presence of a callable Python module as production desktop control. The Phase 1 Tailscale remote enrollment and stable node-to-agent-key binding are still pending.
