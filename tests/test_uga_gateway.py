from __future__ import annotations

from uga.gateway import advertised_tool_names, create_uga_server
from uga.policy import UGA_ALLOWED_TOOLS


def test_knowledge_route_advertises_only_search_and_fetch():
    assert advertised_tool_names(create_uga_server()) == set(UGA_ALLOWED_TOOLS)
