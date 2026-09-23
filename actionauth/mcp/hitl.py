"""Single-agent HITL gate for the MCP surface.

This is the single-agent (no-A2A) analogue of ``actionauth.translation.a2a_mcp``.
Where that module translates an A2A ``auth_required`` event into an MCP
elicitation for a remote agent's action, this gate lets a *single* MCP
agent close the same secure-approval loop with no A2A at all: on an
``ApprovalRequired`` dispatch outcome it emits a URL-mode elicitation
pointing at the independent consent surface, and on a retried tool call it
resumes - reading the human's signed payload from the consent surface,
minting a credential at the delegation authority, and handing back the approval token the
dispatcher needs to execute.

The security core is unchanged: the human signs the exact ``(command,
args)``, the delegation authority mints a single-use credential bound to those bytes, and
the resource server refuses anything else. A2A is one carrier of that
signed approval between processes; this gate is the carrier for the
single-agent case, where the only hop is MCP-host -> consent surface ->
back.

**Resume correlation.** With no A2A ``context_id`` to key on, the consent
session id is derived deterministically from ``(caller, command, args)``
(``consent_session_id``). A retried ``tools/call`` recomputes the same id
and finds its own pending consent - no client-side echo required. The
merged ``SignatureReplay`` guard at the delegation authority prevents a retry from
double-minting.
"""
from __future__ import annotations

import hashlib
import json

from mcp import types as mcp_types

from actionauth.consent.durable_consent import DurableConsentStore
from actionauth.consent.url_mode import ConsentStore
from actionauth.authority import DelegationAuthority, SignedAuthorizationDetails
from actionauth.authority.interface import StateBackend


def consent_session_id(*, caller_id: str, command: str, args: dict) -> str:
    """Deterministic, URL-safe consent-session id for one (caller, action).

    The same caller proposing the same command with the same args always
    yields the same id, so a retried tool call self-correlates to the
    pending consent. Different args (or a different caller) yield a
    different id.
    """
    canonical = json.dumps(
        {"caller": caller_id, "command": command, "args": args},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    return "mcp-" + hashlib.sha256(canonical).hexdigest()[:24]


class _MintedCredentialCache:
    """Durable, TTL-aware cache of an already-minted credential per consent
    session.

    A retried ``tools/call`` (or a replica B that re-presents an approved
    payload) must NOT re-mint: the delegation authority's signature-replay claim rejects a
    second mint of the same signed bytes (``SignatureReplay``). This cache
    remembers the credential that was minted for a given consent session so
    a repeat returns the *same* token instead of raising.

    It is **durable**, not in-process: the backing :class:`StateBackend` is
    the same one the delegation authority uses for its signature/jti/issuance state, so a
    credential minted on replica A is findable by replica B (or a restarted
    bridge) for the same session id. The previous implementation kept this in
    a private ``dict`` on the gate, which (a) vanished on restart and (b) was
    not shared across replicas — exactly the leak item 6 calls out.
    """

    def __init__(self, backend: StateBackend) -> None:
        self._backend = backend

    def get(self, sid: str) -> str | None:
        """Return the cached credential string for ``sid`` or ``None``.

        The credential string is stored in the ``command`` slot of the
        issuance record; ``get_issued`` returns ``None`` once the window has
        closed, so an expired cache entry reads as ``None`` (the caller
        falls through to a fresh mint, which the delegation authority's replay guard
        still protects).
        """
        rec = self._backend.get_issued(sid)
        if rec is None:
            return None
        return rec[0]

    def put(self, sid: str, credential: str, *, exp: int) -> None:
        """Record a minted credential for ``sid`` (first-writer wins).

        .. warning:: credential at rest (reference-implementation caveat)

            ``credential`` is the bearer token, and it is stored
            **unencrypted** (in plaintext) in the ``command`` column of the
            shared issued-credentials table (the same ``StateBackend`` the delegation authority
            uses for its signature/jti/issuance state). ``set_issued`` has
            no encryption and no separate "secret" column; the ``command``
            slot is overloaded to hold it. That is acceptable **only because
            this repository is a reference implementation**: the backing
            store is a process-local / demo SQLite file, never a
            production secret store.

            A production port must give cached credentials their own
            **encrypted-at-rest** storage (e.g. a dedicated column / table,
            or an envelope-encrypted value in a KMS-backed store) rather
            than reusing the plaintext ``command`` slot. Do not copy this
            pattern into a production deployment without that change.
        """
        self._backend.set_issued(
            sid, command=credential, args={}, exp=int(exp), expired_at=float(exp)
        )


class McpHitlGate:
    """Emit a URL-mode elicitation for a HITL-gated action, and resume it.

    Construct with the shared ``ConsentStore`` (also wired into the consent
    server) and the bridge base URL. ``authority`` is required only for
    ``try_resume`` (minting the credential after approval); ``begin`` works
    without it.
    """

    def __init__(
        self,
        *,
        consent_store: ConsentStore | DurableConsentStore,
        bridge_base_url: str,
        rar_type: str,
        authority: DelegationAuthority | None = None,
        state_backend: "StateBackend | None" = None,
    ) -> None:
        self._store = consent_store
        self._base_url = bridge_base_url.rstrip("/")
        self._rar_type = rar_type
        self._authority = authority
        # Durable, TTL-aware cache of already-minted credentials keyed by
        # consent-session id. A retry after a successful mint returns the
        # same token instead of re-presenting the signed payload (which the
        # delegation authority's SignatureReplay would reject).
        #
        # Item 6: this used to be a private ``dict`` on the gate, which
        # (a) vanished on restart and (b) was not shared across replicas —
        # a credential minted on replica A was invisible to replica B,
        # which would re-mint and hit ``SignatureReplay``. The cache now
        # lives in the shared :class:`StateBackend` (the same one the delegation authority
        # uses for its signature/jti/issuance state), so a credential minted
        # on replica A is findable by replica B for the same session id.
        #
        # When ``state_backend`` is not explicitly provided, derive it from
        # the authority (which already owns a durable or default backend); fall
        # back to the process-wide default for authority-less constructions
        # (``begin``-only tests).
        if state_backend is None:
            authority_backend: StateBackend | None = None
            if authority is not None and hasattr(authority, "_durable_state"):
                authority_backend = authority._durable_state  # type: ignore[assignment]
            if authority_backend is None:
                from actionauth.authority.in_memory import get_default_backend
                authority_backend = get_default_backend()
            state_backend = authority_backend
        self._minted = _MintedCredentialCache(state_backend)

    def begin(
        self,
        *,
        command: str,
        args: dict,
        caller_id: str,
        binding_message: str,
    ) -> mcp_types.ElicitRequestURLParams:
        """Create (idempotently) the pending consent session and return the
        URL-mode elicitation the MCP host should open."""
        sid = consent_session_id(caller_id=caller_id, command=command, args=args)
        self._store.create(
            command=command,
            args=args,
            rar_type=self._rar_type,
            approver_id=caller_id,
            binding_message=binding_message,
            session_id=sid,
        )
        return mcp_types.ElicitRequestURLParams(
            mode="url",
            message=binding_message,
            url=f"{self._base_url}/consent/{sid}",
            elicitation_id=sid,
        )

    def try_resume(
        self,
        *,
        command: str,
        args: dict,
        caller_id: str,
    ) -> str | None:
        """If the human has approved this exact action at the consent
        surface, mint a credential and return the approval token the
        dispatcher needs. Return ``None`` if approval is still pending."""
        sid = consent_session_id(caller_id=caller_id, command=command, args=args)
        cached = self._minted.get(sid)
        if cached is not None:
            return cached
        req = self._store.get(sid)
        if req is None or req.signed_payload is None:
            return None
        if self._authority is None:
            raise ValueError("McpHitlGate.try_resume requires a authority to mint")
        signed = SignedAuthorizationDetails(
            command=req.signed_payload["command"],
            args=req.signed_payload["args"],
            rar_type=req.signed_payload["rar_type"],
            exp=req.signed_payload["exp"],
            approver_id=req.signed_payload["approver_id"],
            binding_message=req.signed_payload["binding_message"],
            signature=req.signed_payload["signature"],
        )
        minted = self._authority.mint(signed)
        self._minted.put(sid, minted.credential, exp=minted.exp)
        return minted.credential
