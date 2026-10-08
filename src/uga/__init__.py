"""Unidirectional Gateway Appliance (UGA) — read-only Datacore MCP route."""

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
]
