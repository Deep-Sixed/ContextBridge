"""Owner sign-in with Google (OpenID Connect) on the consent page.

When ``remote.google`` is enabled, approving a remote client takes the owner's
Google account in place of the passphrase, plus the authenticator code as
before. ContextBridge stays the authorization server for MCP clients; Google
only proves who is at the consent page.

* Authorization code flow with PKCE (S256). ``state`` ties the answer to one
  consent request and, through a cookie, to the browser that started it; the
  ``nonce`` must come back inside the ID token.
* The only scopes are ``openid email``: no refresh token and no access to the
  account's Google data.
* The ID token comes straight from Google's token endpoint over TLS, in exchange
  for the code and the client secret, so its claims are checked (issuer,
  audience, expiry, nonce, verified email) without fetching Google's signing
  keys (OpenID Connect Core 3.1.3.7).
* The owner is the configured address. The store pins the account's ``sub`` the
  first time it approves, so a different account later given the same address
  is refused.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

import httpx

AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
ORIGIN = "https://accounts.google.com"
ISSUERS = ("https://accounts.google.com", "accounts.google.com")
SCOPES = "openid email"
CALLBACK_PATH = "/consent/google"
CLIENT_SECRET_ENV = "CONTEXTBRIDGE_GOOGLE_CLIENT_SECRET"
CLOCK_SKEW_SECONDS = 120
TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True)
class GoogleSettings:
    client_id: str
    owner_email: str  # lower case
    client_secret: str = field(repr=False)


class GoogleLoginError(Exception):
    """Sign-in with Google did not prove the owner.

    ``reason`` goes to the audit log. ``counts`` is true when the answer itself was
    wrong (another account, a bad token), which counts toward the consent lockout;
    a cancelled sign-in or an unreachable Google does not.
    """

    def __init__(self, reason: str, *, counts: bool) -> None:
        super().__init__(reason)
        self.reason = reason
        self.counts = counts


def _b64url_json(segment: str) -> dict[str, Any]:
    padded = segment + "=" * (-len(segment) % 4)
    value = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    if not isinstance(value, dict):
        raise ValueError("not a JSON object")
    return value


class GoogleLogin:
    def __init__(
        self,
        settings: GoogleSettings,
        redirect_uri: str,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self.redirect_uri = redirect_uri
        self._transport = transport

    def authorization_url(self, *, state: str, nonce: str, code_challenge: str) -> str:
        params = {
            "client_id": self.settings.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": SCOPES,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "login_hint": self.settings.owner_email,
        }
        return f"{AUTH_ENDPOINT}?{urlencode(params)}"

    async def identify(self, code: str, *, verifier: str, nonce: str) -> tuple[str, str]:
        """Exchange ``code`` and return the signed-in account's (email, sub), or raise GoogleLoginError."""
        if not code:
            raise GoogleLoginError("google_no_code", counts=False)
        claims = self.check_id_token(await self._exchange(code, verifier), nonce=nonce)
        return str(claims["email"]).lower(), str(claims["sub"])

    async def _exchange(self, code: str, verifier: str) -> str:
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": self.redirect_uri,
            "client_id": self.settings.client_id,
            "client_secret": self.settings.client_secret,
        }
        try:
            async with httpx.AsyncClient(transport=self._transport, timeout=TIMEOUT_SECONDS) as http:
                response = await http.post(TOKEN_ENDPOINT, data=data, headers={"Accept": "application/json"})
            body = response.json()
        except (httpx.HTTPError, ValueError):
            raise GoogleLoginError("google_unreachable", counts=False) from None
        id_token = body.get("id_token") if isinstance(body, dict) else None
        if response.status_code != 200 or not isinstance(id_token, str):
            raise GoogleLoginError("google_token_error", counts=False)
        return id_token

    def check_id_token(self, id_token: str, *, nonce: str, now: float | None = None) -> dict[str, Any]:
        """Check the claims of an ID token received directly from Google's token endpoint."""
        now = time.time() if now is None else now
        try:
            _, payload, _ = id_token.split(".")
            claims = _b64url_json(payload)
        except (ValueError, UnicodeError):
            raise GoogleLoginError("invalid_id_token", counts=True) from None
        audience = claims.get("aud")
        audiences = audience if isinstance(audience, list) else [audience]
        exp, iat = claims.get("exp"), claims.get("iat")
        valid = (
            claims.get("iss") in ISSUERS
            and self.settings.client_id in audiences
            and claims.get("azp", self.settings.client_id) == self.settings.client_id
            and isinstance(exp, (int, float)) and exp > now - CLOCK_SKEW_SECONDS
            and isinstance(iat, (int, float)) and iat < now + CLOCK_SKEW_SECONDS
            and isinstance(claims.get("nonce"), str) and secrets.compare_digest(claims["nonce"], nonce)
            and isinstance(claims.get("sub"), str) and claims["sub"]
            and isinstance(claims.get("email"), str) and claims["email"]
        )
        if not valid:
            raise GoogleLoginError("invalid_id_token", counts=True)
        if claims.get("email_verified") not in (True, "true"):
            raise GoogleLoginError("google_email_not_verified", counts=True)
        if claims["email"].lower() != self.settings.owner_email:
            raise GoogleLoginError("wrong_google_account", counts=True)
        return claims
