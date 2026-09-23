"""delegation authority primitives — the cryptographic delegation substrate.

Two implementations of the same ``DelegationAuthority`` Protocol:
  - ``InProcessAuthority``: Tier 1, in-process HMAC verifier
  - ``OAuthAuthority``: Tier 2, JWT-minting authorization server (HS256)

See ``docs/rationale.md`` for the three-tier
graduation and ``docs/architecture.md`` for component flows.
"""
from actionauth.authority.durable_state import DurableReplayState
from actionauth.authority.in_memory import InMemoryStateBackend, get_default_backend, reset_default_backend
from actionauth.authority.in_process import InProcessAuthority, sign_authorization_details
from actionauth.authority.interface import (
    CredentialDrift,
    CredentialExpired,
    CredentialReplay,
    MalformedCredential,
    MintedCredential,
    PayloadDriftAtMint,
    PolicyDenied,
    SignatureMismatch,
    SignatureReplay,
    SignedAuthorizationDetails,
    StateBackend,
    UnknownIssuer,
    DelegationAuthority,
    AuthorityError,
    WrongAudience,
)
from actionauth.authority.oauth import OAuthAuthority

__all__ = [
    "CredentialDrift",
    "CredentialExpired",
    "CredentialReplay",
    "DurableReplayState",
    "InMemoryStateBackend",
    "InProcessAuthority",
    "MalformedCredential",
    "MintedCredential",
    "OAuthAuthority",
    "PayloadDriftAtMint",
    "PolicyDenied",
    "SignatureMismatch",
    "SignatureReplay",
    "SignedAuthorizationDetails",
    "StateBackend",
    "UnknownIssuer",
    "DelegationAuthority",
    "AuthorityError",
    "WrongAudience",
    "get_default_backend",
    "reset_default_backend",
    "sign_authorization_details",
]
