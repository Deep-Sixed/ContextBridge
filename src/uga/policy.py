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


# The filesystem route (uga.fs_gateway) is a separate server with its own allowlist.
FS_READ_TOOLS: frozenset[str] = frozenset(
    {
        "read_file",
        "read_multiple_files",
        "list_directory",
        "get_file_info",
        # Search sessions only read files; they are offered with read-only roots too.
        "start_search",
        "get_more_search_results",
        "stop_search",
        "list_searches",
    }
)
# Advertised only when at least one configured root is writable.
FS_WRITE_TOOLS: frozenset[str] = frozenset(
    {"write_file", "edit_block", "create_directory", "move_file", "delete_file"}
)
