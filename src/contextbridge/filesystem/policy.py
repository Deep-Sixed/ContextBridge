"""Filesystem route tool policy: an explicit allowlist, default-deny."""

from __future__ import annotations

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
