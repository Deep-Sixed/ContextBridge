# ContextBridge ChatGPT plugin

Source for the private ContextBridge plugin, version 0.1.2.

- Display name: ContextBridge
- MCP server key: `contextbridge`
- Endpoint: `https://nexusagi.tail9cb382.ts.net:8443/mcp`
- Plugin: https://chatgpt.com/plugins/plugins_6ae1d055074c8191bcf023a51de68a8f

The internal package name `nexus-agi` is retained to preserve the existing plugin identity. The endpoint hostname is unchanged. User-facing descriptions and the default prompt use ContextBridge.

## Package

From the repository root, build an archive outside the package directory:

```sh
python -m zipfile -c contextbridge-plugin.zip plugins/contextbridge/plugin.json plugins/contextbridge/mcp.json
```

This creates a portable archive containing the two required files at its root. The `.codex-plugin/plugin.json` and `.mcp.json` files in this directory are compatibility overlays retained from the saved plugin release.

Upload the archive through Plugin Creator to update the existing plugin; do not create a duplicate. The remote server remains separately hosted. No credentials are included. Authentication and tool discovery remain unverified: the setup probe returned HTTP 503. Saving this package does not prove server connectivity.
