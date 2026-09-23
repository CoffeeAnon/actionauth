"""OAuthAuthority: Tier 2 JWT-minting verifier.

Tier 2 differs from Tier 1 in shape but holds the same security properties:
parameter-binding, single-use, expiry, signature verification. Plus: the
minted credential is a structurally distinct JWT (not the same HMAC the
user signed), so capturing the user's signed payload is not sufficient to
forge a credential.
"""
import time

import pytest

from actionauth.authority import (
    CredentialDrift,
    CredentialExpired,
    CredentialReplay,
    MalformedCredential,
    OAuthAuthority,
    PayloadDriftAtMint,
    SignatureMismatch,
    SignatureReplay,
    UnknownIssuer,
    WrongAudience,
    sign_authorization_details,
)


USER_SECRET = "user-side-signing-secret-32bytes-pad"
MINT_SECRET = "authority-mint-secret-32bytes-padding-x"
RAR_TYPE = "tasktracker_task_action"


@pytest.fixture
def authority():
    return OAuthAuthority(
        user_signing_secret=USER_SECRET,
        mint_secret=MINT_SECRET,
        expected_rar_type=RAR_TYPE,
    )


def _signed(command="delete-task", args=None, secret=USER_SECRET, binding_message="Delete task t-42?"):
    return sign_authorization_details(
        command=command,
        args=args or {"task_id": "t-42"},
        rar_type=RAR_TYPE,
        approver_id="alice",
        binding_message=binding_message,
        secret=secret,
    )


# ── mint produces a JWT distinct from the input ────────────────────────────


def test_minted_credential_is_a_jwt(authority):
    signed = _signed()
    minted = authority.mint(signed)
    assert minted.credential.count(".") == 2
    # Credential is NOT equal to the input signature; it's a freshly-issued JWT.
    assert minted.credential != signed.signature


def test_minted_credential_contains_authorization_details(authority):
    """The Tier-2-distinctive property: claim-bearing token."""
    import base64
    import json

    signed = _signed()
    minted = authority.mint(signed)
    _h, body_b64, _sig = minted.credential.split(".")
    body = json.loads(base64.urlsafe_b64decode(body_b64 + "=" * (-len(body_b64) % 4)))
    assert body["authorization_details"][0]["command"] == "delete-task"
    assert body["authorization_details"][0]["args"] == {"task_id": "t-42"}
    assert body["authorization_details"][0]["type"] == RAR_TYPE
    assert body["sub"] == "alice"


# ── mint rejections ─────────────────────────────────────────────────────────


def test_mint_rejects_bad_user_signature(authority):
    signed = _signed(secret="wrong-user-secret-16bytes-yes")
    with pytest.raises(SignatureMismatch):
        authority.mint(signed)


def test_mint_rejects_unexpected_rar_type():
    authority = OAuthAuthority(
        user_signing_secret=USER_SECRET,
        mint_secret=MINT_SECRET,
        expected_rar_type="some_other_type",
    )
    with pytest.raises(PayloadDriftAtMint):
        authority.mint(_signed())


def test_mint_rejects_signature_replay(authority):
    """Consent Atomicity at Tier 2: one signed payload mints at most one
    credential. The delegation authority tracks canonical-bytes hashes of signed payloads
    accepted at mint and refuses to mint twice from the same one."""
    signed = _signed()
    first = authority.mint(signed)
    with pytest.raises(SignatureReplay):
        authority.mint(signed)
    # The first credential is unaffected and consumes normally.
    authority.consume(first.credential, "delete-task", {"task_id": "t-42"})


# ── consume: parameter binding through JWT claims ──────────────────────────


def test_consume_happy_path(authority):
    minted = authority.mint(_signed())
    consumed = authority.consume(minted.credential, "delete-task", {"task_id": "t-42"})
    assert consumed.jti == minted.jti


def test_consume_rejects_drifted_args(authority):
    minted = authority.mint(_signed(args={"task_id": "approved"}))
    with pytest.raises(CredentialDrift):
        authority.consume(minted.credential, "delete-task", {"task_id": "drifted"})


def test_consume_rejects_drifted_command(authority):
    minted = authority.mint(_signed(command="delete-task"))
    with pytest.raises(CredentialDrift):
        authority.consume(minted.credential, "update-task", {"task_id": "t-42"})


# ── consume: replay ────────────────────────────────────────────────────────


def test_consume_rejects_replay(authority):
    minted = authority.mint(_signed())
    authority.consume(minted.credential, "delete-task", {"task_id": "t-42"})
    with pytest.raises(CredentialReplay):
        authority.consume(minted.credential, "delete-task", {"task_id": "t-42"})


# ── consume: tampering ─────────────────────────────────────────────────────


def test_consume_rejects_tampered_jwt(authority):
    minted = authority.mint(_signed())
    # Flip the last character of the signature.
    bad = minted.credential[:-1] + ("A" if minted.credential[-1] != "A" else "B")
    with pytest.raises(SignatureMismatch):
        authority.consume(bad, "delete-task", {"task_id": "t-42"})


def test_consume_rejects_jwt_from_a_different_authority():
    """A JWT minted by one delegation authority must not validate against another."""
    authority_a = OAuthAuthority(user_signing_secret=USER_SECRET, mint_secret="authority-A-mint-secret-32bytes-padding")
    authority_b = OAuthAuthority(user_signing_secret=USER_SECRET, mint_secret="authority-B-mint-secret-32bytes-padding")
    minted = authority_a.mint(_signed())
    with pytest.raises(SignatureMismatch):
        authority_b.consume(minted.credential, "delete-task", {"task_id": "t-42"})


# ── consume: structural + identity failures (distinct from signature) ──


def test_consume_rejects_malformed_jwt(authority):
    """Token has no dots: not structurally a JWT."""
    with pytest.raises(MalformedCredential):
        authority.consume("not-a-jwt", "delete-task", {"task_id": "t-42"})


def test_consume_rejects_alg_none_attack(authority):
    """Forge a JWT with ``alg=none`` and an empty signature. Algorithm-
    pinning must reject before any signature comparison happens."""
    import json
    from actionauth.authority.oauth import _b64url

    header_b64 = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    body_b64 = _b64url(json.dumps({
        "iss": "https://authority.reference.invalid",
        "aud": "bridge-resource-server",
        "exp": 9999999999,
        "jti": "forged",
        "authorization_details": [{
            "type": RAR_TYPE, "command": "delete-task", "args": {"task_id": "t-42"},
        }],
    }).encode())
    forged = f"{header_b64}.{body_b64}."  # empty signature

    with pytest.raises(MalformedCredential):
        authority.consume(forged, "delete-task", {"task_id": "t-42"})


def test_consume_rejects_alg_rs256_attack(authority):
    """Algorithm-confusion defence: a token with ``alg=RS256`` (or any
    non-HS256 alg) must be rejected before HMAC verification. This is
    the structural defence against the textbook RS256→HS256
    key-confusion vulnerability when the delegation authority eventually swaps
    algorithms in a production deployment."""
    import json
    from actionauth.authority.oauth import _b64url

    header_b64 = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    body_b64 = _b64url(json.dumps({
        "iss": "https://authority.reference.invalid", "aud": "bridge-resource-server",
        "exp": 9999999999, "jti": "rs256-forged",
        "authorization_details": [{
            "type": RAR_TYPE, "command": "delete-task", "args": {"task_id": "t-42"},
        }],
    }).encode())
    # Sign with our HS256 secret as if the attacker had key-confused us.
    import hashlib as _h, hmac as _hmac
    sig = _b64url(_hmac.new(MINT_SECRET.encode(), f"{header_b64}.{body_b64}".encode(), _h.sha256).digest())
    forged = f"{header_b64}.{body_b64}.{sig}"

    with pytest.raises(MalformedCredential):
        authority.consume(forged, "delete-task", {"task_id": "t-42"})


def test_consume_rejects_malformed_jwt_body(authority):
    """Three dot-separated parts, signature verifies, but body is not JSON.

    Constructed by signing a junk body with the delegation authority's own mint secret so
    we get past the signature check and exercise the body-decode failure
    path; an unusual but real adversary scenario (malicious mint, bug).
    """
    import hashlib as _h
    import hmac as _hmac
    from actionauth.authority.oauth import _b64url

    header_b64 = _b64url(b'{"alg":"HS256","typ":"JWT"}')
    body_b64 = _b64url(b"not valid json {{{")
    signing_input = f"{header_b64}.{body_b64}".encode()
    sig_b64 = _b64url(_hmac.new(MINT_SECRET.encode(), signing_input, _h.sha256).digest())
    bad_token = f"{header_b64}.{body_b64}.{sig_b64}"

    with pytest.raises(MalformedCredential):
        authority.consume(bad_token, "delete-task", {"task_id": "t-42"})


def test_consume_rejects_unknown_issuer():
    """Token validates cryptographically but iss does not match this delegation authority."""
    minter = OAuthAuthority(
        user_signing_secret=USER_SECRET,
        mint_secret=MINT_SECRET,
        issuer="https://other-authority.example.invalid",
    )
    validator = OAuthAuthority(
        user_signing_secret=USER_SECRET,
        mint_secret=MINT_SECRET,
        issuer="https://expected-authority.example.invalid",
    )
    minted = minter.mint(_signed())
    with pytest.raises(UnknownIssuer):
        validator.consume(minted.credential, "delete-task", {"task_id": "t-42"})


def test_consume_rejects_wrong_audience():
    """Token validates cryptographically but aud is for a different RS."""
    minter = OAuthAuthority(
        user_signing_secret=USER_SECRET,
        mint_secret=MINT_SECRET,
        audience="rs-A",
    )
    validator = OAuthAuthority(
        user_signing_secret=USER_SECRET,
        mint_secret=MINT_SECRET,
        audience="rs-B",
    )
    minted = minter.mint(_signed())
    with pytest.raises(WrongAudience):
        validator.consume(minted.credential, "delete-task", {"task_id": "t-42"})


# ── consume: expiry ───────────────────────────────────────────────────────


def test_mint_rejects_expired_signed_payload(authority):
    """The delegation authority is the policy point for credential lifetime. A signer
    that submits an already-expired payload is rejected at mint time,
    not silently minted into an immediately-stale JWT."""
    stale = sign_authorization_details(
        command="delete-task", args={"task_id": "t-42"}, rar_type=RAR_TYPE,
        approver_id="alice", binding_message="Delete task t-42?",
        secret=USER_SECRET, ttl_seconds=-60,
    )
    with pytest.raises(CredentialExpired):
        authority.mint(stale)


def test_mint_rejects_overlong_ttl():
    """A signer that proposes a decade-long ``exp`` is rejected at mint.
    The delegation authority's ``max_signed_payload_ttl_seconds`` is the policy bound."""
    authority = OAuthAuthority(
        user_signing_secret=USER_SECRET,
        mint_secret=MINT_SECRET,
        expected_rar_type=RAR_TYPE,
        max_signed_payload_ttl_seconds=300,
    )
    # Sign with a 10x-over-policy TTL.
    signed = sign_authorization_details(
        command="delete-task", args={"task_id": "t-42"}, rar_type=RAR_TYPE,
        approver_id="alice", binding_message="Delete task t-42?",
        secret=USER_SECRET, ttl_seconds=3000,
    )
    with pytest.raises(PayloadDriftAtMint, match="exceeds delegation authority max_ttl"):
        authority.mint(signed)


def test_mint_accepts_within_ttl_bounds():
    """Sanity: an ``exp`` within bounds is fine."""
    authority = OAuthAuthority(
        user_signing_secret=USER_SECRET,
        mint_secret=MINT_SECRET,
        expected_rar_type=RAR_TYPE,
        max_signed_payload_ttl_seconds=600,
    )
    signed = sign_authorization_details(
        command="delete-task", args={"task_id": "t-42"}, rar_type=RAR_TYPE,
        approver_id="alice", binding_message="Delete task t-42?",
        secret=USER_SECRET, ttl_seconds=300,
    )
    # Should not raise.
    minted = authority.mint(signed)
    assert minted.exp > int(time.time())


def test_consume_rejects_expired(authority, monkeypatch):
    signed = sign_authorization_details(
        command="delete-task",
        args={"task_id": "t-42"},
        rar_type=RAR_TYPE,
        approver_id="alice",
        binding_message="Delete task t-42?",
        secret=USER_SECRET,
        ttl_seconds=1,
    )
    minted = authority.mint(signed)
    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() + 10)
    with pytest.raises(CredentialExpired):
        authority.consume(minted.credential, "delete-task", {"task_id": "t-42"})
