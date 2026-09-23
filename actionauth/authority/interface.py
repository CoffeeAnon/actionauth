"""delegation authority interface: the cryptographic delegation engine.

Every tier of the bridge expresses its trust substrate through a delegation authority.
At Tier 1 (`InProcessAuthority`) the delegation authority is an in-process HMAC verifier.
At Tier 2 (`OAuthAuthority`) it is an external authorization server that mints
JWTs with `authorization_details` claims. Both honour the same interface
and the same contract:

  - **mint**: verify the human's signature over a structured authorization
    payload (the RAR `authorization_details`) and return a single-use,
    short-lived credential bound to those exact parameters.
  - **consume**: validate the credential against a live command + args at
    execution time, mark it consumed, and reject replays.

The dispatcher only ever calls ``consume``. The bridge layer calls ``mint``
in response to an elicitation approval and passes the resulting
``MintedCredential`` to the dispatcher.

The security property this contract carries (per ``docs/rationale.md``)
is parameter-binding: the credential is pinned to the exact arguments the
human approved. ``DelegationAuthority.mint`` is where that pin is set, and ``DelegationAuthority.consume``
is where it is enforced. A delegation authority implementation that fails either step
breaks the property and the design contract.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class AuthorityError(Exception):
    """Raised on any verification failure inside the delegation authority.

    Subclasses below let callers distinguish *what* failed, which matters
    because each failure mode tells a different audit story:

      - ``MalformedCredential``      → bug, integration error, or fuzzing
      - ``SignatureMismatch``        → cryptographic forgery attempt
      - ``UnknownIssuer`` / ``WrongAudience`` → token from another system
      - ``PayloadDriftAtMint``       → client signed something other than proposed
      - ``CredentialDrift``          → live request doesn't match what was approved
      - ``CredentialExpired``        → time bound exceeded
      - ``CredentialReplay``         → single-use violation (at consume)
      - ``SignatureReplay``          → multi-mint violation (at mint): same
                                       signed payload presented to the delegation authority
                                       more than once
      - ``PolicyDenied``             → identity lacks the requested permission
                                       (reserved for production AS-side policy;
                                       not raised by the in-process or HS256 demos —
                                       ``approver_id`` is carried for attribution,
                                       not enforced as authorization policy)

    The dispatcher treats every ``AuthorityError`` uniformly as "approval required"
    when surfacing to callers, but the typed exception is preserved on the
    ``ApprovalRequired.reason`` field for audit attribution.
    """


class MalformedCredential(AuthorityError):
    """Credential's wire format is structurally broken (e.g., not three
    dot-separated parts for a JWT, body is not valid base64-JSON).
    Distinct from ``SignatureMismatch`` because no cryptographic check
    was attempted: there was nothing to check."""


class SignatureMismatch(AuthorityError):
    """Cryptographic verification failed: the HMAC or JWT signature does
    not match the expected value computed with the configured secret.
    Raised only after the credential has been confirmed structurally
    well-formed."""


class UnknownIssuer(AuthorityError):
    """JWT validates cryptographically but the ``iss`` claim does not
    match this delegation authority's expected issuer. Common cause: token minted by a
    different delegation authority deployment, or client misconfigured to point at the
    wrong AS."""


class WrongAudience(AuthorityError):
    """JWT validates cryptographically but the ``aud`` claim does not
    match this resource server's expected audience. Common cause: token
    minted for a different resource server in a multi-RS deployment."""


class PayloadDriftAtMint(AuthorityError):
    """Signature is valid but the payload contents do not match the
    authorization_details the bridge emitted (i.e., the client signed
    something other than what was proposed)."""


class PolicyDenied(AuthorityError):
    """Signature and payload are valid but delegation authority policy refuses to mint
    (e.g., the approver's identity lacks the requested permission).

    Reserved for production AS-side authorization decisions. **Neither the
    in-process delegation authority nor the HS256 OAuthAuthority demo raises this**: they treat
    ``approver_id`` as an attribution field carried through to the audit log
    and the JWT ``sub`` claim, not as input to an RBAC/ABAC decision. A
    production AS swapped in behind the ``DelegationAuthority`` Protocol (Keycloak,
    Authlete, Auth0, Curity, etc.) is where this exception would actually
    surface.
    """


class CredentialReplay(AuthorityError):
    """Credential has already been consumed."""


class SignatureReplay(AuthorityError):
    """The same signed RAR payload was presented to the delegation authority more than once.

    Distinct from ``CredentialReplay``, which fires at *consume* when a minted
    credential is presented twice. ``SignatureReplay`` fires at *mint*: it
    closes the multi-mint surface where one human signature could otherwise
    be exchanged for N distinct, valid credentials within the signed-payload
    TTL. The delegation authority tracks consumed signed-payload signatures and refuses to
    mint twice from the same one. One signature = one credential = one
    execution.

    The property this protects is "fresh consent per execution," not just
    "fresh consent per action shape." Captured signed payloads cannot be
    replayed by an attacker holding the bytes (e.g., a leaked WebSocket
    frame, a misbehaving relay, a compromised bridge process)."""


class CredentialExpired(AuthorityError):
    """Credential's `exp` is in the past."""


class CredentialDrift(AuthorityError):
    """Credential's bound parameters do not match the live request."""


@dataclass(frozen=True)
class SignedAuthorizationDetails:
    """The payload the human signs after reviewing an elicitation.

    Fields:
      command:               canonical command name (e.g. "delete-task")
      args:                  exact arguments the human approved
      rar_type:              the RAR `authorization_details.type` string
      exp:                   POSIX seconds (integer; truncated for
                             cross-language byte-stability; see
                             ``actionauth/authority/CANONICAL.md``)
      approver_id:           opaque approver identity (for audit)
      binding_message:       human-readable summary the user actually read
                             at the consent surface (e.g., "Delete the task
                             titled 'Q2 launch checklist'?"). Included in
                             the canonical bytes so that what the user
                             *saw* is cryptographically bound to what they
                             *signed*. A compromised bridge that renders
                             one message and signs different bytes will
                             fail delegation authority verification; see ``SECURITY.md``.
      signature:             HMAC-SHA256 over the canonical JSON of
                             {command, args, rar_type, exp, approver_id,
                             binding_message}
    """
    command: str
    args: dict
    rar_type: str
    exp: int
    approver_id: str
    binding_message: str
    signature: str


@dataclass(frozen=True)
class MintedCredential:
    """The credential the delegation authority hands back after a successful mint.

    Tier 1: ``credential`` is the HMAC + a jti suffix.
    Tier 2: ``credential`` is a freshly-minted JWT (HS256 in the reference;
    asymmetric in production) carrying ``authorization_details``.

    The dispatcher does not need to know which tier produced the
    credential - it only knows to pass it to ``DelegationAuthority.consume`` at
    execution time.

    Fields ``command`` and ``args`` are deliberately denormalised with the
    opaque ``credential`` string: callers (audit, logging, the dispatcher's
    ``ApprovalRequired.reason`` plumbing) need the bound parameters in a
    structured form without re-decoding the credential. The delegation authority's
    ``consume`` method is the source of truth for whether the bound
    parameters match the live request - these fields exist for
    *attribution*, not for authorization decisions.
    """
    credential: str
    command: str
    args: dict
    exp: int
    jti: str  # unique identifier for single-use tracking


class DelegationAuthority(Protocol):
    """The trust substrate. Tier 1 and Tier 2 implement this identically
    from the dispatcher's point of view."""

    def mint(self, signed: SignedAuthorizationDetails) -> MintedCredential:
        """Verify the human's signature; return a single-use, action-scoped
        credential bound to the approved arguments. Raises ``AuthorityError``
        subclass on any failure."""
        ...

    def consume(self, credential: str, command: str, args: dict) -> MintedCredential:
        """Validate the credential at execution time, mark it consumed.
        Returns the parsed MintedCredential (useful for audit). Raises
        ``AuthorityError`` subclass on any failure."""
        ...


class StateBackend(Protocol):
    """The single-use / replay-state substrate a delegation authority or Resource Server
    delegates its "one token = one execution" decision to.

    Why a protocol
    --------------
    A *stateless* bridge does not make its replay state safe across replicas.
    ``InProcessAuthority``, ``OAuthAuthority`` and ``JwtResourceServer`` each enforce
    single-use with an in-process set that (a) vanishes on restart and (b) is
    **not shared across processes**. Two bridge replicas, or a restart inside
    the 5-minute TTL, each start with an empty set, so a captured-but-not-
    yet-replayed signed payload or credential can be re-minted / re-consumed.

    This is the seam that closes that surface: the delegation authority/RS delegate the
    load-bearing single-use decision to a ``StateBackend`` instance it is
    *given* at construction, rather than holding private in-process sets.
    The reference ships two backends that both satisfy this protocol:

      - :class:`actionauth.authority.durable_state.DurableReplayState` — a SQLite file
        (WAL, ``INSERT OR IGNORE`` CAS) that survives restart and is shared
        across replicas when the file is on shared storage.
      - :class:`actionauth.authority.in_memory.InMemoryStateBackend` — a thread-safe
        dict, for single-process tests (and, when constructed with a shared
        backing dict, for the "two backend instances sharing one dict"
        acceptance test that simulates replica B).

    Method vocabulary (the reviewer's "get / set / delete + TTL / CAS")
    -----------------------------------------------------------------
    - ``claim_signature`` / ``claim_jti`` — the **set** + atomic CAS: record a
      signed payload (mint) or a credential ``jti`` (consume); return ``True``
      only for the *first* presentation, ``False`` for a replay.
    - ``is_signature_consumed`` / ``is_jti_consumed`` — the **get**: read-only
      membership check (audit, exception-ordering pre-checks).
    - ``purge_expired`` — the **delete** (TTL): reclaim rows whose validity
      window has closed. Explicit housekeeping, never automatic.

    ``DurableReplayState`` and ``InMemoryStateBackend`` are both structural
    subtypes of this protocol (Python ``typing.Protocol`` — no ABC
    inheritance required); a backend need only define the five methods with
    compatible signatures.
    """

    def claim_signature(self, sig_hash: str, *, expired_at: float) -> bool:
        """Mint-time CAS. ``True`` only for the *first* presentation of
        ``sig_hash``; ``False`` for any later presentation (a replay)."""
        ...

    def is_signature_consumed(self, sig_hash: str) -> bool:
        """Get. ``True`` if ``sig_hash`` has a record, regardless of window."""
        ...

    def claim_jti(self, jti: str, *, expired_at: float) -> bool:
        """Consume-time CAS. ``True`` only for the *first* consume of ``jti``;
        ``False`` for any later consume (a replay)."""
        ...

    def is_jti_consumed(self, jti: str) -> bool:
        """Get. ``True`` if ``jti`` has a record, regardless of window."""
        ...

    def purge_expired(self) -> int:
        """Delete (TTL). Drop records whose validity window has closed; return
        the count purged. Explicit housekeeping only."""
        ...

    def set_issued(self, jti: str, *, command: str, args: dict,
                   exp: int, expired_at: float) -> bool:
        """Record a Tier-1 issuance (mint): what the credential authorises
        (``command``/``args``), its claim-level expiry (``exp``), and the
        record's validity window (``expired_at``). Backends MUST be atomic:
        a second ``set_issued`` for the same ``jti`` returns ``False`` so a
        concurrent double-mint cannot overwrite the first record. Callers
        that already hold a successful ``claim_signature`` for the same
        payload may treat the call as idempotent, but the backend still
        reports whether it was the first writer."""
        ...

    def get_issued(self, jti: str) -> tuple[str, dict, int] | None:
        """Get the Tier-1 issuance record for ``jti`` (``command``,
        ``args``, ``exp``) or ``None`` if unknown/expired."""
        ...
