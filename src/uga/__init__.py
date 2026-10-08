"""Unidirectional Gateway Appliance (UGA) — read-only Datacore MCP route."""

from .adapter import (
    DatacoreFetchRecord,
    DatacoreRecordError,
    DatacoreRecordNotFound,
    DatacoreStore,
    default_jsonl_path,
)
from .policy import UGA_ALLOWED_TOOLS, UGA_FORBIDDEN_TOOL_EXAMPLES

__all__ = [
    "DatacoreFetchRecord",
    "DatacoreRecordError",
    "DatacoreRecordNotFound",
    "DatacoreStore",
    "UGA_ALLOWED_TOOLS",
    "UGA_FORBIDDEN_TOOL_EXAMPLES",
    "default_jsonl_path",
]
