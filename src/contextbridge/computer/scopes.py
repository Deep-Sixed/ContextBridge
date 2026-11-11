"""The scopes a caller's token, a device grant, and a federated MCP server can name."""

from __future__ import annotations

SCOPE_READ = "computer:read"
SCOPE_WRITE = "computer:write"
SCOPE_EXECUTE = "computer:execute"
SCOPE_PROCESS = "computer:process"
SCOPE_DESKTOP_OBSERVE = "desktop:observe"
SCOPE_MEDIA_DISCOVER = "media:discover"
ALL_SCOPES = (SCOPE_READ, SCOPE_WRITE, SCOPE_EXECUTE, SCOPE_PROCESS, SCOPE_DESKTOP_OBSERVE, SCOPE_MEDIA_DISCOVER)
