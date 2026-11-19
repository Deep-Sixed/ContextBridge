"""The ContextBridge mark: a suspension bridge between network nodes, as one small SVG.

Served as the favicon at ``/favicon.svg`` (and ``/favicon.ico``) and drawn inline in the dashboard.
"""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import Response

LOGO_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect x="1" y="1" width="62" height="62" rx="15" fill="#071233"/><g stroke="#1aa3ff" stroke-width="1.8" stroke-linecap="round"><path d="M9.5 23 15 32 9.5 41M54.5 23 49 32 54.5 41"/></g><g fill="none" stroke="#1aa3ff" stroke-linecap="round" stroke-linejoin="round"><path d="M15 32Q20.5 30.5 24.5 23Q32 37 39.5 23Q43.5 30.5 49 32" stroke-width="2.2"/><path d="M24.5 23v16M39.5 23v16" stroke-width="3"/><path d="M28 27.6V32M32 29.7V32M36 27.6V32M20.5 29.3V32M43.5 29.3V32" stroke-width="1.2"/><path d="M18 34.5Q23 35 23.5 39M24.5 34Q32 33 39.5 34M40.5 39Q41 35 46 34.5" stroke-width="2.2"/></g><path d="M16.5 32H47.5" stroke="#3ff3ff" stroke-width="3" stroke-linecap="round" stroke-dasharray="9 2.5"/><g fill="#0b1d4a" stroke="#ffffff" stroke-width="1.6"><circle cx="9.5" cy="23" r="3"/><circle cx="9.5" cy="41" r="3"/><circle cx="54.5" cy="23" r="3"/><circle cx="54.5" cy="41" r="3"/><circle cx="15" cy="32" r="3.6"/><circle cx="49" cy="32" r="3.6"/></g></svg>'
)


async def favicon(request: Request) -> Response:
    return Response(
        LOGO_SVG,
        media_type="image/svg+xml",
        headers={
            "Cache-Control": "public, max-age=86400",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
        },
    )


def logo(size: int) -> str:
    """The mark inline at ``size`` pixels, for pages that should not fetch it."""
    return LOGO_SVG.replace("<svg ", f'<svg width="{size}" height="{size}" aria-hidden="true" ', 1)
