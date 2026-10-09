"""UGA gateway tool policy — explicit allowlist, default-deny."""

from __future__ import annotations

UGA_ALLOWED_TOOLS: frozenset[str] = frozenset({"search", "fetch"})

# Examples used in tests and docs; not an exhaustive deny list because default-deny
# applies to anything outside UGA_ALLOWED_TOOLS.
UGA_FORBIDDEN_TOOL_EXAMPLES: frozenset[str] = frozenset(
    {
        "shell",
        "list_directory",
        "filesystem",
        "docker",
        "systemctl",
        "keepass",
        "writeback",
        "metadata_exchange_record_task_completion",
    }
)


def is_tool_allowed(name: str) -> bool:
    return name in UGA_ALLOWED_TOOLS
