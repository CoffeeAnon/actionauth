"""MCP auth: bearer-token verification using the shared TokenStore.

verify_bearer() raises AuthError with a discriminating reason on failure;
the server.py middleware translates these into 401 responses.
"""
from __future__ import annotations

from actionauth.auth.hmac import CallerIdentity, TokenStore, caller_from_token


class AuthError(Exception):
    """Auth verification failed. The reason argument matches log/audit conventions."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def verify_bearer(authorization_header: str, store: TokenStore, secret: str) -> CallerIdentity:
    """Validate `Authorization: Bearer <token>` and return the caller identity.

    Raises AuthError(reason) where reason is one of:
      missing_header, invalid_hmac, revoked
    """
    if not authorization_header or not authorization_header.startswith("Bearer "):
        raise AuthError("missing_header")
    token = authorization_header.removeprefix("Bearer ").strip()
    if not token:
        raise AuthError("missing_header")
    if store.is_revoked(token, secret):
        raise AuthError("revoked")
    try:
        return caller_from_token(token, store, secret)
    except ValueError as exc:
        raise AuthError("invalid_hmac") from exc
