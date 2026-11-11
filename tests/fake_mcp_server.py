"""A small stdio MCP server standing in for agent-desktop or Playwright MCP in federation tests."""

from __future__ import annotations

import base64
import os
import sys
import time

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from mcp.types import ImageContent

PNG = base64.b64encode(b"\x89PNG\r\n\x1a\nfake").decode("ascii")

server = FastMCP("fake")


@server.tool
def echo(text: str) -> dict:
    """Return the text it was given."""
    return {"echo": text, "pid": os.getpid()}


@server.tool
def fake_snapshot() -> ImageContent:
    """Return a tiny image (already named with the server prefix)."""
    return ImageContent(type="image", data=PNG, mimeType="image/png")


@server.tool
def fail(reason: str = "nope") -> str:
    """Always report an error."""
    raise ToolError(f"failed: {reason}")


@server.tool
def slow(seconds: float) -> str:
    """Sleep, then answer."""
    time.sleep(seconds)
    return "done"


@server.tool
def crash() -> str:
    """Exit the server process without answering."""
    os._exit(3)


@server.tool
def aim(device: str) -> str:
    """Takes its own 'device' argument, so the gateway cannot offer it."""
    return device


@server.tool
def env(name: str) -> str:
    """Report an environment variable."""
    return os.environ.get(name, "<unset>")


if __name__ == "__main__":
    print("fake MCP server starting", file=sys.stderr, flush=True)
    server.run(transport="stdio", show_banner=False)
