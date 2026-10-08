"""Remote MCP access for ChatGPT, Claude, and other OAuth MCP clients.

A minimal, self-hosted OAuth 2.1 authorization server for the computer route:
Dynamic Client Registration limited to known redirect hosts, PKCE, resource-bound
opaque tokens, refresh-token rotation with reuse detection, and an owner consent
step that requires a passphrase and a TOTP code and lets the owner choose which
scopes and devices each client receives.
"""
