"""URL-mode elicitation consent surface.

The MCP specification 2025-11-25 introduced two elicitation modes:
``form`` for structured-data collection and ``url`` for out-of-band
interactions that must not pass through the MCP client. The spec
REQUIRES URL mode for any interaction involving sensitive credentials
(OAuth authorization, payment processing, key material). Our consent
step is an OAuth-style authorization flow, so it MUST use URL mode.

This module provides the bridge's URL-mode elicitation surface as a
minimal Starlette mount with three endpoints:

  GET  /consent/<session_id>           renders the HTML consent page
                                       with the proposed authorization_details
  POST /consent/<session_id>/submit    handles the page's Approve / Deny
                                       button. In this *demo*, Approve
                                       triggers server-side signing via
                                       ``demo_sign_as_user`` over the stored
                                       ``ProposedAction`` — no signed payload
                                       crosses the wire. A production
                                       deployment with client-side signing
                                       (WebAuthn / Passkey) would receive a
                                       signed payload here and MUST verify
                                       its (command, args, rar_type,
                                       approver_id) match the stored
                                       ``ProposedAction`` before calling
                                       ``DelegationAuthority.mint``. The demo skips that
                                       check because the demo cannot drift
                                       by construction; production can.
  GET  /consent/<session_id>/result    poll endpoint for the bridge's
                                       elicitation handler; returns
                                       404 until approved, then the
                                       signed payload

This is a *reference*. It intentionally has no styling, no auth, no
durable session store. A production deployment would add user
authentication on the consent page, a session store backed by Redis
or sqlite, CSRF protection on the POST, and a real signing flow
(probably WebAuthn / Passkeys to remove the HMAC-secret dependence).
The shape of the flow is what carries over to production - the
implementation here does not.

**Demo-mode key-residence warning.** The reference's ``build_consent_app``
takes a ``user_signing_secret`` and passes it to ``demo_sign_as_user``,
a server-side stand-in for what a real client-side WebAuthn assertion
or passkey would do. This means **in the reference, the bridge process
holds the user signing key**. A bridge compromise in this configuration
is equivalent to a human-key compromise: the attacker can fabricate
signed authorization-details for any action without any human involvement.
This is acceptable for a self-contained demo (the demo must run without
a separate user-key custodian), but it is *not* the threat model
``docs/architecture.md`` commits Tier 2 to. In production,
``user_signing_secret`` must live on the human's MCP host (or on a
hardware-backed key store the human controls), and the bridge must
NEVER hold it. The ``actionauth.consent.demo_signer`` module is the seam
to replace.
"""
from __future__ import annotations

import copy
import html
import json
import secrets
import threading
import time
import types
from dataclasses import dataclass, field
from collections.abc import Mapping

from starlette.applications import Starlette
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route

from actionauth.consent.demo_signer import demo_sign_as_user


@dataclass(frozen=True)
class ProposedAction:
    """The action the bridge is asking the human to approve.

    Frozen by design: once the bridge emits an elicitation describing
    this action, the action's fields MUST NOT change between display
    and signing. The delegation authority's binding property ("the credential is
    bound to the parameters the human approved") reduces to this
    immutability plus the canonical-bytes contract.

    Construct via ``ProposedAction.create(...)`` rather than the
    raw constructor: ``create`` deep-copies ``args`` and wraps it in
    a ``MappingProxyType`` so that *both* re-assignment AND in-place
    mutation are blocked. ``@dataclass(frozen=True)`` alone is a
    shallow freeze and would not protect ``action.args["k"] = v``
    from mutating the stored dict.
    """
    session_id: str
    command: str
    args: Mapping[str, object]      # populated by create() as MappingProxyType
    rar_type: str
    approver_id: str
    binding_message: str
    created_at: float = field(default_factory=time.time)

    @classmethod
    def create(
        cls,
        *,
        session_id: str,
        command: str,
        args: Mapping[str, object],
        rar_type: str,
        approver_id: str,
        binding_message: str,
    ) -> ProposedAction:
        """Construct a ProposedAction with deep-copied, read-only args.

        Why both deep-copy AND MappingProxyType:
          - Deep-copy snapshots the args at create time; subsequent
            mutations to the caller's original dict do not affect us.
          - MappingProxyType makes the stored mapping read-only,
            so a future code path that holds a reference to
            ``action.args`` cannot mutate it (e.g.,
            ``action.args["x"] = y`` raises TypeError).
        Together with ``@dataclass(frozen=True)``, this gives full
        structural immutability of the action description.
        """
        return cls(
            session_id=session_id,
            command=command,
            args=types.MappingProxyType(copy.deepcopy(dict(args))),
            rar_type=rar_type,
            approver_id=approver_id,
            binding_message=binding_message,
        )


@dataclass
class ConsentRequest:
    """A pending elicitation: the (immutable) proposed action plus the
    (mutable) human response state.

    Splitting these is the structural enforcement of the
    "bridge signs over the emitted authorization_details" property:
    the response state (signed_payload, denied) is mutable because
    that's the whole point of the consent flow, but the action
    description is frozen so the bridge cannot alter what the human
    is being asked to sign once the request exists.
    """
    action: ProposedAction
    signed_payload: dict | None = None  # populated on successful submit
    denied: bool = False

    # Convenience pass-throughs for templates / external readers; reading
    # via the action attribute is also fine.
    @property
    def session_id(self) -> str:
        return self.action.session_id

    @property
    def command(self) -> str:
        return self.action.command

    @property
    def args(self) -> dict:
        return self.action.args

    @property
    def rar_type(self) -> str:
        return self.action.rar_type

    @property
    def approver_id(self) -> str:
        return self.action.approver_id

    @property
    def binding_message(self) -> str:
        return self.action.binding_message

    @property
    def created_at(self) -> float:
        return self.action.created_at


class ConsentStore:
    """Thread-safe in-memory store. Single-process only.

    Production deployments should swap this for a Redis-backed store with
    TTL eviction so the consent page can survive bridge restarts.
    """

    def __init__(self) -> None:
        self._requests: dict[str, ConsentRequest] = {}
        self._lock = threading.Lock()

    def create(
        self,
        *,
        command: str,
        args: dict,
        rar_type: str,
        approver_id: str,
        binding_message: str,
        session_id: str | None = None,
    ) -> ConsentRequest:
        """Create (or return the existing) consent request for ``session_id``.

        ``session_id`` defaults to a fresh random token (the A2A flow, where
        the bridge mints an opaque elicitation id). The single-agent MCP gate
        passes a *deterministic* id derived from ``(caller, command, args)`` so
        a retried ``tools/call`` self-correlates to the same pending consent;
        in that case a create for an id that already exists is idempotent and
        returns the existing request rather than overwriting it.
        """
        session_id = session_id or secrets.token_urlsafe(16)
        with self._lock:
            existing = self._requests.get(session_id)
            if existing is not None:
                return existing
        action = ProposedAction.create(
            session_id=session_id,
            command=command,
            args=args,
            rar_type=rar_type,
            approver_id=approver_id,
            binding_message=binding_message,
        )
        req = ConsentRequest(action=action)
        with self._lock:
            existing = self._requests.get(session_id)
            if existing is not None:
                return existing
            self._requests[session_id] = req
        return req

    def get(self, session_id: str) -> ConsentRequest | None:
        with self._lock:
            return self._requests.get(session_id)

    def submit_signed(self, session_id: str, signed_payload: dict) -> bool:
        with self._lock:
            req = self._requests.get(session_id)
            if req is None or req.signed_payload is not None or req.denied:
                return False
            req.signed_payload = signed_payload
            return True

    def deny(self, session_id: str) -> bool:
        with self._lock:
            req = self._requests.get(session_id)
            if req is None or req.signed_payload is not None or req.denied:
                return False
            req.denied = True
            return True


_CONSENT_PAGE_TEMPLATE = """<!DOCTYPE html>
<html><head><title>Approve action</title>
<style>body{{font-family:sans-serif;max-width:600px;margin:2em auto;}}
.action{{background:#fff7d6;padding:1em;border-left:4px solid #d8a800;}}
.params{{font-family:monospace;background:#f5f5f5;padding:1em;white-space:pre-wrap;}}
.btn{{padding:0.6em 1.2em;margin:0.5em 0.5em 0 0;cursor:pointer;}}
.approve{{background:#1d6b1d;color:white;border:none;}}
.deny{{background:#aa1d1d;color:white;border:none;}}</style></head>
<body>
<h2>Approve agent action</h2>
<div class="action">
  <p><strong>{binding_message}</strong></p>
  <p>The agent is requesting permission to perform:</p>
  <div class="params">
command: {command}
args:    {args_pretty}
type:    {rar_type}
  </div>
  <p>Approving this credential authorises <em>this exact action with these
  exact arguments</em>, single-use, valid for 5 minutes. Any other action,
  or this action with different arguments, will require separate approval.</p>
</div>
<form method="POST" action="/consent/{session_id}/submit">
  <button class="btn approve" type="submit" name="decision" value="approve">Approve</button>
  <button class="btn deny" type="submit" name="decision" value="deny">Deny</button>
</form>
</body></html>
"""


def render_consent_page(req: ConsentRequest) -> str:
    """Render the consent page with every interpolated value HTML-escaped.

    Every string interpolated into the template originates from the agent
    (binding_message, command, args, rar_type) or from the bridge
    (session_id). All of those are attacker-influenceable in the general
    case: a task title becomes a binding_message, and an LLM-proposed
    arg becomes part of args_pretty. Without escaping, a malicious task
    title could inject a `<script>` or swap out the form's action URL,
    defeating the entire point of human review.

    ``html.escape`` covers `&`, `<`, `>`, `"`, and `'`.
    """
    return _CONSENT_PAGE_TEMPLATE.format(
        binding_message=html.escape(req.binding_message),
        command=html.escape(req.command),
        # dict() unwraps the MappingProxyType so json.dumps can serialise it.
        args_pretty=html.escape(json.dumps(dict(req.args), indent=2)),
        rar_type=html.escape(req.rar_type),
        session_id=html.escape(req.session_id),
    )


def build_consent_app(
    *,
    store: ConsentStore,
    user_signing_secret: str,
) -> Starlette:
    """Build a Starlette sub-app exposing the consent endpoints.

    ``user_signing_secret`` is the secret the user-side signing function
    uses. In a real deployment the user would hold this key; in the
    reference it's shared with the delegation authority for simplicity.
    """

    async def _render(request) -> Response:
        session_id = request.path_params["session_id"]
        req = store.get(session_id)
        if req is None:
            return HTMLResponse("<h3>Unknown consent session</h3>", status_code=404)
        if req.signed_payload is not None:
            return HTMLResponse("<h3>Already approved.</h3>")
        if req.denied:
            return HTMLResponse("<h3>Denied.</h3>")
        return HTMLResponse(render_consent_page(req))

    async def _submit(request) -> Response:
        session_id = request.path_params["session_id"]
        req = store.get(session_id)
        if req is None:
            return HTMLResponse("<h3>Unknown consent session</h3>", status_code=404)

        form = await request.form()
        decision = form.get("decision", "")

        if decision == "deny":
            store.deny(session_id)
            return HTMLResponse("<h3>Denied.</h3>")

        if decision != "approve":
            return HTMLResponse("<h3>Bad decision</h3>", status_code=400)

        signed = demo_sign_as_user(
            command=req.command,
            args=req.args,
            rar_type=req.rar_type,
            approver_id=req.approver_id,
            binding_message=req.binding_message,
            user_secret=user_signing_secret,
        )
        store.submit_signed(session_id, signed)
        return HTMLResponse("<h3>Approved. You may close this window.</h3>")

    async def _result(request) -> Response:
        session_id = request.path_params["session_id"]
        req = store.get(session_id)
        if req is None:
            return JSONResponse({"error": "unknown session"}, status_code=404)
        if req.denied:
            return JSONResponse({"status": "denied"}, status_code=200)
        if req.signed_payload is None:
            return JSONResponse({"status": "pending"}, status_code=202)
        return JSONResponse({"status": "approved", "signed": req.signed_payload})

    return Starlette(routes=[
        Route("/consent/{session_id}", _render, methods=["GET"]),
        Route("/consent/{session_id}/submit", _submit, methods=["POST"]),
        Route("/consent/{session_id}/result", _result, methods=["GET"]),
    ])
