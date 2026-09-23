"""Tier 1 delegation authority: in-process HMAC verifier.

No external authorization server, no JWT minting, no JWKS: just an HMAC
over the canonical authorization-details payload, verified in-process by
the same dispatcher that will execute the action. The delegation authority's ``mint``
step is essentially a no-op: it confirms the signature is valid, records
the credential as "issued and unconsumed", and returns the same HMAC as
the minted credential.

This is what the substrate ships. It carries the parameter-binding
property end-to-end through one process, with one shared secret. The
trade-off is documented in the rationale page "Three deployment tiers":
Tier 1 closes LLM-side threats (prompt injection, parameter drift,
hallucinated arguments) but does NOT defend against agent-process
compromise.

Migrating to Tier 2 is an additive swap: replace the InProcessAuthority with
an OAuthAuthority while keeping the dispatcher's ``consume`` call identical.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time

import types

from actionauth.authority.interface import (
    CredentialDrift,
    CredentialExpired,
    CredentialReplay,
    MalformedCredential,
    MintedCredential,
    PayloadDriftAtMint,
    SignatureMismatch,
    SignatureReplay,
    SignedAuthorizationDetails,
    DelegationAuthority,
)
from actionauth.authority.durable_state import DurableReplayState


_DEFAULT_MAX_SIGNED_PAYLOAD_TTL_SECONDS = 600  # see actionauth/authority/oauth.py


def _canonical_default(obj):
    """JSON encoder hook for read-only mapping types.

    ``actionauth.consent.url_mode.ProposedAction`` stores ``args`` as a
    ``types.MappingProxyType`` to make the action description immutable
    after creation. ``json.dumps`` doesn't know how to serialise
    MappingProxyType natively, so we provide a default that unwraps
    it to a plain dict for serialization. The contents are the same
    snapshot the proxy guards: bytes-identical to a hand-built dict
    from the same source.
    """
    if isinstance(obj, types.MappingProxyType):
        return dict(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _reject_floats(value, path: str = "args") -> None:
    """Recursively reject ``float`` values anywhere in ``args``.

    Floats have no stable cross-language canonical representation:
    ``0.1 + 0.2`` may serialise as ``0.30000000000000004`` on one
    platform and ``0.3`` on another, and Python's ``json.dumps`` and
    JavaScript's ``JSON.stringify`` disagree on edge cases (subnormals,
    very large magnitudes). A reference that teaches a canonical-form
    contract cannot leave that drift surface unaddressed. Callers that
    need fractional quantities must encode them as integers in a fixed
    minor unit (e.g., cents instead of dollars) or as strings.
    ``bool`` is intentionally allowed; ``bool`` is a subclass of
    ``int`` in Python but ``isinstance(True, float)`` is False.
    """
    if isinstance(value, float):
        raise TypeError(
            f"canonical_authorization_bytes: float values are not permitted "
            f"in args (at {path}); use integer minor units or strings. "
            f"See the Floats section of actionauth/authority/CANONICAL.md."
        )
    if isinstance(value, dict) or isinstance(value, types.MappingProxyType):
        for k, v in value.items():
            _reject_floats(v, path=f"{path}.{k}")
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            _reject_floats(v, path=f"{path}[{i}]")


def canonical_authorization_bytes(
    command: str, args: dict, rar_type: str, exp: int, approver_id: str,
    binding_message: str,
) -> bytes:
    """Canonical JSON serialization for HMAC computation.

    Properties (formal spec lives in ``actionauth/authority/CANONICAL.md``):
      - sorted keys at every nesting level (``sort_keys=True``)
      - tight separators, no whitespace (``separators=(",", ":")``)
      - ``exp`` is integer seconds since epoch (no float repr drift)
      - **floats are rejected** anywhere in ``args``; see ``_reject_floats``
      - list order is *significant*: the human approves [a,b] vs [b,a]
        as different actions
      - string values are caller's responsibility to NFC-normalise
      - ``args`` may be a plain ``dict`` or a ``types.MappingProxyType``
        (used by the consent server to make stored args immutable);
        both produce byte-identical output.
      - ``binding_message`` is included so the human-readable summary the
        user actually read is cryptographically bound to the signature.
        Without it a compromised bridge could render "Delete tmp file"
        while signing bytes for "Delete production DB". See the
        "binding_message" section of ``CANONICAL.md`` and ``SECURITY.md``.

    This is the load-bearing function: if signer and verifier disagree
    about the canonical form, the signature mismatches. Public so Tier 1
    and Tier 2 delegation authority implementations can share one definition. The spec
    document is the contract for cross-language signer implementations.
    """
    _reject_floats(args)
    return json.dumps(
        {
            "cmd": command, "args": args, "rar_type": rar_type,
            "exp": exp, "approver_id": approver_id,
            "binding_message": binding_message,
        },
        sort_keys=True,                  # recursive key sort at every nesting level
        separators=(",", ":"),           # no whitespace anywhere
        ensure_ascii=True,               # explicit: see actionauth/authority/CANONICAL.md "Non-ASCII strings"
        default=_canonical_default,      # serialise MappingProxyType (immutable args) as plain dict
    ).encode()


def sign_authorization_details(
    *,
    command: str,
    args: dict,
    rar_type: str,
    approver_id: str,
    binding_message: str,
    secret: str,
    ttl_seconds: int = 300,
) -> SignedAuthorizationDetails:
    """Helper for the MCP host / client side: produce the signed payload
    that gets POSTed to the delegation authority. In production this lives in the MCP
    client's elicitation handler, not on the agent service side.

    ``exp`` is computed as integer seconds since epoch to keep the
    canonical bytes byte-stable across language implementations
    (Python's ``float`` repr would not match e.g. JavaScript's).
    """
    exp = int(time.time()) + ttl_seconds
    payload_bytes = canonical_authorization_bytes(
        command, args, rar_type, exp, approver_id, binding_message,
    )
    signature = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
    return SignedAuthorizationDetails(
        command=command, args=args, rar_type=rar_type, exp=exp,
        approver_id=approver_id, binding_message=binding_message,
        signature=signature,
    )


class InProcessAuthority(DelegationAuthority):
    """Tier 1 delegation authority. Thread-safe single-use enforcement delegated to a
    shared :class:`StateBackend`. Production deployments inject a
    :class:`~actionauth.authority.durable_state.DurableReplayState` (SQLite file,
    shared across replicas); the default is the process-wide
    :func:`actionauth.authority.in_memory.get_default_backend` singleton so that
    even two default-constructed delegation authorities in one process share the same
    replay/issuance state.

    **Issuance-record note.** The credential's *issuance* record
    (``set_issued``/``get_issued`` on the backend) is stored in the shared
    backend, not in a private dict: a credential minted on replica A and
    presented to replica B resolves its binding data from the shared store.
    Under the default in-process singleton a restart still loses the record
    (process-local dict), and a post-restart replay then fails with
    ``SignatureMismatch`` — the documented Tier-1 restart behaviour. With an
    injected :class:`DurableReplayState`, issuance records survive restart
    too: a replayed payload is rejected by the shared signature table, and a
    replayed credential is rejected by the shared jti table.

    **Mint-replay closure.** ``claim_signature`` on the backend tracks
    canonical-bytes hashes of signed payloads accepted at ``mint``. A second
    presentation of the same signed payload raises ``SignatureReplay``
    rather than producing a fresh credential. One human signature exchanges
    for one credential.
    """

    def __init__(
        self,
        *,
        secret: str,
        expected_rar_type: str | None = None,
        max_signed_payload_ttl_seconds: int = _DEFAULT_MAX_SIGNED_PAYLOAD_TTL_SECONDS,
        durable_state: "DurableReplayState | None" = None,
        # Persisted storage key, not a display name: consumed-jti rows in an
        # existing durable backend were written under "vault", so the default
        # keeps that value after the component was renamed. Changing
        # it would let already-consumed credentials replay until they expire.
        jti_namespace: str = "vault",
    ) -> None:
        from actionauth.authority.in_memory import get_default_backend
        from actionauth.authority.oauth import _require_nonempty_secret
        _require_nonempty_secret("secret", secret)
        if max_signed_payload_ttl_seconds <= 0:
            raise ValueError("max_signed_payload_ttl_seconds must be > 0")
        if not jti_namespace:
            raise ValueError("jti_namespace must be a non-empty string")
        self._secret = secret
        self._expected_rar_type = expected_rar_type
        self._max_ttl = max_signed_payload_ttl_seconds
        # C3/C4: no private in-process sets. Every in-scope category
        # (signature claim, jti claim, issuance record) lives in the
        # shared backend. Default-constructed delegation authorities share the
        # process-wide default backend, so two default delegation authorities minting
        # the same signed payload can no longer both succeed (NEGCTRL-1).
        #
        # ``jti_namespace`` isolates the consumed-jti table per
        # component *family* (default "vault", a persisted key): the three-layer
        # architecture requires the Resource Server's consumed-jti state
        # to be independent of the delegation authority's, so an RS-backed deployment
        # passes ``jti_namespace="rs"``. The *signature* table is never
        # namespaced — mint-replay must stay shared across all
        # components (one signature = one credential).
        self._durable_state = durable_state if durable_state is not None else get_default_backend()
        self._jti_namespace = jti_namespace
        self._lock = threading.Lock()

    def mint(self, signed: SignedAuthorizationDetails) -> MintedCredential:
        # 1. Verify HMAC.
        canonical = canonical_authorization_bytes(
            signed.command, signed.args, signed.rar_type,
            signed.exp, signed.approver_id, signed.binding_message,
        )
        expected = hmac.new(
            self._secret.encode(),
            canonical,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, signed.signature):
            raise SignatureMismatch("HMAC verification failed")

        # 1b. Enforce signer-side `exp` bounds. The delegation authority is the policy
        #     point for credential lifetime; a signer that proposes a
        #     decade-long exp or an already-expired exp is rejected at
        #     mint time.
        now = time.time()
        if signed.exp <= now:
            raise CredentialExpired(
                f"signed payload exp={signed.exp} is already in the past (now={now:.0f})"
            )
        if signed.exp > now + self._max_ttl:
            raise PayloadDriftAtMint(
                f"signed payload exp={signed.exp} exceeds delegation authority max_ttl of "
                f"{self._max_ttl}s (would be {signed.exp - now:.0f}s out)"
            )

        # 2. Validate the rar_type if the delegation authority was configured with one.
        if self._expected_rar_type is not None and signed.rar_type != self._expected_rar_type:
            raise PayloadDriftAtMint(
                f"unexpected rar_type: {signed.rar_type!r} != {self._expected_rar_type!r}"
            )

        # 3. Signature-replay check + record, then mint. The check-and-record
        #    is delegated to the shared backend (atomic in the DB / under the
        #    backend lock), so two *replicas* racing on the same payload
        #    cannot both win. Runs after structural validation so an invalid
        #    payload cannot poison the store.
        #
        #    C4: the Tier-1 issuance record is written to the same shared
        #    backend (``set_issued``), so a credential minted on replica A
        #    can be consumed on replica B.
        signature_hash = hashlib.sha256(canonical).hexdigest()
        jti = secrets.token_hex(8)
        credential = f"{signed.signature}.{jti}"
        minted = MintedCredential(
            credential=credential,
            command=signed.command,
            args=signed.args,
            exp=signed.exp,
            jti=jti,
        )
        first = self._durable_state.claim_signature(
            signature_hash, expired_at=float(signed.exp)
        )
        if not first:
            raise SignatureReplay(
                "signed payload already exchanged for a credential; "
                "one signature = one credential = one execution"
            )
        self._durable_state.set_issued(
            jti,
            command=signed.command,
            args=dict(signed.args),
            exp=signed.exp,
            expired_at=float(signed.exp),
        )
        return minted

    def consume(self, credential: str, command: str, args: dict) -> MintedCredential:
        try:
            _sig, jti = credential.rsplit(".", 1)
        except ValueError as exc:
            raise MalformedCredential("Tier-1 credential must be 'signature.jti'") from exc

        # C4: the issuance record lives in the shared backend, not a
        # private dict — so a credential minted on replica A and presented
        # to replica B resolves its binding data from the shared store.
        record = self._durable_state.get_issued(jti)
        if record is None:
            raise SignatureMismatch(
                "credential jti was not issued by this delegation authority (no issuance "
                "record in the shared state backend — it may have expired "
                "or the delegation authority was restarted without a durable backend)"
            )
        issued_command, issued_args, issued_exp = record

        # Durable consume: the shared store is the single-use authority.
        # Order mirrors the historical in-memory path (replay, then
        # expired, then binding) so a replayed/Drifted/Expired credential
        # reports the same reason it used to. The atomic claim at the end
        # is the load-bearing cross-replica decision; the pre-checks are
        # for stable, drift-independent messages. Jti keys are namespaced
        # so the delegation authority's consumed-jti table stays independent of the RS's
        # (three-layer architecture), while every other table (signature,
        # issuance) is shared.
        ns_jti = f"{self._jti_namespace}:{jti}"
        if self._durable_state.is_jti_consumed(ns_jti):
            raise CredentialReplay(f"credential {jti} already consumed")
        if time.time() > issued_exp:
            raise CredentialExpired(f"credential {jti} expired")
        if issued_command != command:
            raise CredentialDrift(
                f"credential bound to command={issued_command!r}, live command={command!r}"
            )
        if issued_args != args:
            raise CredentialDrift(
                f"credential bound to args={issued_args!r}, live args={args!r}"
            )
        first = self._durable_state.claim_jti(ns_jti, expired_at=float(issued_exp))
        if not first:
            # Lost the race: another replica/attempt consumed it first.
            raise CredentialReplay(f"credential {jti} already consumed")
        return MintedCredential(
            credential=credential,
            command=issued_command,
            args=issued_args,
            exp=issued_exp,
            jti=jti,
        )
