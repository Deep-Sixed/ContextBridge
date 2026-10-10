"""Unidirectional Gateway Appliance (UGA) — read-only Datacore MCP route.

The separate filesystem route lives in ``uga.fs`` and ``uga.fs_gateway``.
"""

from .adapter import (
    DatacoreFetchRecord,
    DatacoreRecordError,
    DatacoreRecordNotFound,
    DatacoreStore,
)
from .policy import UGA_ALLOWED_TOOLS, UGA_FORBIDDEN_TOOL_EXAMPLES

# Single source of truth: pyproject.toml reads this, and the MCP server reports it.
__version__ = "0.1.0"

__all__ = [
    "DatacoreFetchRecord",
    "DatacoreRecordError",
    "DatacoreRecordNotFound",
    "DatacoreStore",
    "UGA_ALLOWED_TOOLS",
    "UGA_FORBIDDEN_TOOL_EXAMPLES",
    "__version__",
]
