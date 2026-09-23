"""Shared HMAC bearer-token primitives.

Used by the MCP surface (``actionauth.mcp.auth.verify_bearer``) to
authenticate inbound HTTP requests. The token store is file-backed
JSON keyed by an HMAC hash of the bearer string; ``CallerIdentity``
encapsulates the resolved subject for audit attribution.

This package depends only on stdlib — no Starlette, no SDK imports.
The MCP surface is the only intra-repo consumer; structuring it as a
shared package leaves room for future protocol surfaces (a future
A2A executor would consume the same primitives without duplication).
"""
