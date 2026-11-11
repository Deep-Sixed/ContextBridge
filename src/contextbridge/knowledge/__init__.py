"""ContextBridge knowledge route: read-only ``search`` and ``fetch`` over approved records.

The filesystem route lives in ``contextbridge.filesystem``, the computer route in
``contextbridge.computer``.
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
from .policy import KNOWLEDGE_ALLOWED_TOOLS, KNOWLEDGE_FORBIDDEN_TOOL_EXAMPLES

__all__ = [
    "DatacoreFetchRecord",
    "DatacoreRecordError",
    "DatacoreRecordNotFound",
    "DatacoreStore",
    "KNOWLEDGE_ALLOWED_TOOLS",
    "KNOWLEDGE_FORBIDDEN_TOOL_EXAMPLES",
    "__version__",
]
