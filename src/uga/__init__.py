"""Unidirectional Gateway Appliance (UGA) — read-only Datacore MCP route.

The separate filesystem route lives in ``uga.fs`` and ``uga.fs_gateway``.
"""

# One version for the whole distribution: pyproject.toml reads contextbridge.__version__,
# and both MCP servers report it.
from contextbridge import __version__

from .adapter import (
    DatacoreFetchRecord,
    DatacoreRecordError,
    DatacoreRecordNotFound,
    DatacoreStore,
)
from .policy import UGA_ALLOWED_TOOLS, UGA_FORBIDDEN_TOOL_EXAMPLES

__all__ = [
    "DatacoreFetchRecord",
    "DatacoreRecordError",
    "DatacoreRecordNotFound",
    "DatacoreStore",
    "UGA_ALLOWED_TOOLS",
    "UGA_FORBIDDEN_TOOL_EXAMPLES",
    "__version__",
]
