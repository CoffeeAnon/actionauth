"""Separated Resource Server with independent JWT validation.

In the three-layer architecture documented in `docs/architecture.md` (rationale page "How the bridge
weaves the tiers together"; architecture page "Component map"), the
delegation authority mints credentials and the Resource Server validates them
*independently* — same JWT, separate validation path, separate state.

This module provides ``JwtResourceServer``, the executable counterpart
to the architecture page's "Resource server" component. The dispatcher
forwards a (command, args, credential) tuple to the RS; the RS does its
own JWT verify, ``iss``/``aud``/``exp`` checks, ``authorization_details``
binding check against the live request, and single-use enforcement
against its *own* consumed-jti set. If everything passes, the RS
executes the action against the underlying tool client.

Why separation matters even in this HS256-based reference:

  - **Independence of state**: the delegation authority's consumed-jti set and the RS's
    consumed-jti set are different objects. A bug or compromise in one
    does not affect the other. The "three independent enforcement
    layers" claim documented in ``docs/architecture.md`` requires this.
  - **Independence of validation**: the RS validates the JWT against its
    own configured verification key. In HS256 the symmetric secret is
    the same as the mint secret (a limitation of HS256); in the
    production RS256/ES256 deployment the RS holds only the delegation authority's
    *public* key. Compromising the RS does not yield mint capability in
    that production deployment. **In the HS256 reference, RS compromise
    does yield mint capability — this is an HS256-specific weakness, not
    an architectural one.** Documented honestly here for that reason.

The dispatcher's role becomes purely "hold the HITL gate; forward to RS
once approved." Validation and execution happen at the RS, not at the
dispatcher. This matches the component diagram in `docs/architecture.md`.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any

from actionauth.core.client import ApiError
from actionauth.core.registry import REGISTRY
from actionauth.authority.interface import (
    CredentialDrift,
    CredentialExpired,
    CredentialReplay,
    MalformedCredential,
    SignatureMismatch,
    UnknownIssuer,
    WrongAudience,
)
from actionauth.authority.oauth import _audience_matches, jwt_decode
from actionauth.authority.durable_state import DurableReplayState


# ── RS-level outcomes ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class RsSuccess:
    items: list[dict]
    meta: dict


@dataclass(frozen=True)
class RsError:
    status: int | str
    message: str
    context: dict | None


@dataclass(frozen=True)
class RsRejected:
    """The RS refused to execute because credential validation failed."""
    reason: str
    detail: str


RsOutcome = RsSuccess | RsError | RsRejected


# ── Resource server ─────────────────────────────────────────────────────────


class JwtResourceServer:
    """RS that validates delegation authority-minted JWTs independently of the delegation authority.

    Configured with:
      - ``verification_secret``: the symmetric secret used to verify HS256
        signatures (production: RSA/EC public key for asymmetric algs).
        Same value as the delegation authority's ``mint_secret`` in HS256 reference;
        would be the delegation authority's *public* key in a production RS256/ES256
        deployment.
      - ``expected_issuer`` / ``expected_audience``: claims the RS pins
        every accepted JWT to.
      - ``expected_rar_type``: optional defence-in-depth check that the
        ``authorization_details[0].type`` matches this RS's domain.
      - ``client``: the underlying tool client (e.g. an in-memory store
        in the reference; an HTTP client in production).

    The RS maintains single-use state (``claim_jti``) in its ``durable_state``
    backend — by default the process-wide
    :func:`actionauth.authority.in_memory.get_default_backend` singleton, independent
    of the delegation authority's backend. A token marked consumed at the delegation authority is *not*
    automatically consumed at the RS, and vice versa, unless both are
    configured with the same injected backend.

    **Restart-replay limitation.** When no backend is injected, the default
    (in-memory) singleton is in-process memory. An RS restart inside the JWT
    TTL discards the consumed record, so a captured-but-not-replayed JWT
    becomes replayable until its ``exp`` passes. Inject a
    :class:`~actionauth.authority.durable_state.DurableReplayState` on shared
    storage to close that window. Within one process, default-constructed
    RS instances share the same backend, so replay protection is active
    across components even with no injection.
    """

    def __init__(
        self,
        *,
        verification_secret: str,
        expected_issuer: str,
        expected_audience: str,
        client: Any,
        expected_rar_type: str | None = None,
        durable_state: "DurableReplayState | None" = None,
    ) -> None:
        from actionauth.authority.oauth import _require_nonempty_secret
        _require_nonempty_secret("verification_secret", verification_secret)
        if not expected_issuer:
            raise ValueError("JwtResourceServer requires a non-empty expected_issuer")
        if not expected_audience:
            raise ValueError("JwtResourceServer requires a non-empty expected_audience")
        self._verification_secret = verification_secret
        self._expected_issuer = expected_issuer
        self._expected_audience = expected_audience
        self._expected_rar_type = expected_rar_type
        self._client = client
        # C3: no private in-process set — consumed-jti single-use state
        # lives in the shared backend. Default-constructed RS instances
        # share the process-wide default backend.
        from actionauth.authority.in_memory import get_default_backend
        self._durable_state = durable_state if durable_state is not None else get_default_backend()
        self._lock = threading.Lock()

    def execute(self, command: str, args: dict, credential: str) -> RsOutcome:
        """Validate the credential against the live request, then execute.

        Validation order (matches ``OAuthAuthority.consume`` for consistency):
          1. JWT decode + cryptographic verify
          2. exp / iss / aud
          3. authorization_details presence
          4. single-use (before binding check)
          5. command + args binding
          6. rar_type (defence in depth)
        """
        # 1. structural + cryptographic
        try:
            claims = jwt_decode(credential, self._verification_secret)
        except (MalformedCredential, SignatureMismatch) as exc:
            return RsRejected(reason=type(exc).__name__, detail=str(exc))

        # 2. temporal + identity
        try:
            self._validate_claims(claims)
        except (CredentialExpired, UnknownIssuer, WrongAudience) as exc:
            return RsRejected(reason=type(exc).__name__, detail=str(exc))

        # 3-6. authorization_details + single-use + binding
        try:
            jti = self._consume_authorization_details(claims, command, args)
        except (
            MalformedCredential, CredentialReplay, CredentialDrift,
        ) as exc:
            return RsRejected(reason=type(exc).__name__, detail=str(exc))

        # All checks passed. Execute the underlying command.
        return self._execute_command(command, args, jti)

    # ── private validators ─────────────────────────────────────────────

    def _validate_claims(self, claims: dict) -> None:
        # exp is integer seconds per CANONICAL.md spec; the RS treats it
        # as such (matches OAuthAuthority.consume and prevents accepting
        # spec-violating float exp values).
        if time.time() > int(claims.get("exp", 0)):
            raise CredentialExpired(f"jti={claims.get('jti')} expired at RS")
        if claims.get("iss") != self._expected_issuer:
            raise UnknownIssuer(
                f"token iss={claims.get('iss')!r} != RS expected {self._expected_issuer!r}"
            )
        if not _audience_matches(claims.get("aud"), self._expected_audience):
            raise WrongAudience(
                f"token aud={claims.get('aud')!r} != RS expected {self._expected_audience!r}"
            )

    def _consume_authorization_details(self, claims: dict, command: str, args: dict) -> str:
        ad_list = claims.get("authorization_details") or []
        if not ad_list:
            raise MalformedCredential("token has no authorization_details claim")
        ad = ad_list[0]

        jti = claims.get("jti", "")
        # C3: the shared backend is the single-use authority for every
        # construction — a JWT consumed on one RS/replica is rejected on
        # another. Order mirrors the historical in-memory path: single-use
        # before binding; the atomic claim at the end is the load-bearing
        # cross-replica decision.
        if self._durable_state.is_jti_consumed(jti):
            raise CredentialReplay(f"jti={jti} already consumed by RS")
        if ad.get("command") != command:
            raise CredentialDrift(
                f"token bound to command={ad.get('command')!r}, RS asked for {command!r}"
            )
        if ad.get("args") != args:
            raise CredentialDrift(
                f"token bound to args={ad.get('args')!r}, RS asked for {args!r}"
            )
        if self._expected_rar_type is not None and ad.get("type") != self._expected_rar_type:
            raise CredentialDrift(
                f"token rar_type={ad.get('type')!r} != RS expected {self._expected_rar_type!r}"
            )
        first = self._durable_state.claim_jti(jti, expired_at=float(int(claims.get("exp", 0))))
        if not first:
            raise CredentialReplay(f"jti={jti} already consumed by RS")
        return jti

    # ── private executor ───────────────────────────────────────────────

    def _execute_command(self, command: str, args: dict, jti: str) -> RsOutcome:
        cmd_cls = REGISTRY.get(command)
        if cmd_cls is None:
            return RsError(status="unknown", message=f"Unknown command: {command}", context=None)

        try:
            items = cmd_cls().execute(client=self._client, **args)
        except ApiError as e:
            return RsError(status=e.status_code, message=e.body, context=dict(args))
        except ValueError as e:
            return RsError(status=400, message=str(e), context=dict(args))

        meta = {**args, "count": len(items), "status": "ok", "consumed_jti": jti}
        return RsSuccess(items=items, meta=meta)
