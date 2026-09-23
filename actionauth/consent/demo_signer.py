"""DEMO-ONLY: server-side stand-in for client-side signing.

In a production deployment the signing step is performed *by the human's
MCP host* (Claude Desktop, IDE, custom orchestrator) using a credential
the human controls — ideally a WebAuthn / Passkey assertion, not a shared
HMAC secret. The MCP host POSTs the resulting signed payload to the
bridge's consent endpoint.

For the reference's self-contained demo we cannot launch a separate
client process during a single ``pytest`` run, so this module provides
a *fake signer* that runs server-side and signs on the user's behalf.
**This module is one of the lines a real deployment would replace.**
``url_mode.py`` carries the *shape* of a URL-mode consent surface, but
production must additionally add consent-page user authentication,
CSRF protection, a durable session store, and (with client-side
signing in place) a payload-vs-stored-``ProposedAction`` check before
calling ``DelegationAuthority.mint``. See README "Demo implementation shortcuts" and
``SECURITY.md`` for the full list.

The fake signer delegates to ``actionauth.authority.sign_authorization_details``
so the demo cannot accidentally drift from the delegation authority's canonical-bytes
definition. If the canonical form ever changes in one place but not
the other, every demo test fails immediately.
"""
from __future__ import annotations

from actionauth.authority import sign_authorization_details


def demo_sign_as_user(
    *,
    command: str,
    args: dict,
    rar_type: str,
    approver_id: str,
    binding_message: str,
    user_secret: str,
    ttl_seconds: int = 300,
) -> dict:
    """Produce a signed authorization-details payload as if the user-side
    MCP host had done so. Returns the wire format the bridge expects on
    the consent submit endpoint.

    DO NOT call this from production code paths. The user_secret should
    not exist on the server side at all in a real deployment.
    """
    signed = sign_authorization_details(
        command=command,
        args=args,
        rar_type=rar_type,
        approver_id=approver_id,
        binding_message=binding_message,
        secret=user_secret,
        ttl_seconds=ttl_seconds,
    )
    return {
        "command": signed.command,
        # Convert to a plain dict for the wire — args may have been a
        # MappingProxyType when sourced from a ProposedAction. The wire
        # format is JSON; immutability was an in-process binding property.
        "args": dict(signed.args),
        "rar_type": signed.rar_type,
        "exp": signed.exp,
        "approver_id": signed.approver_id,
        "binding_message": signed.binding_message,
        "signature": signed.signature,
    }
