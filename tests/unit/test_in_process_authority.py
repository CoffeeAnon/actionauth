"""InProcessAuthority - Tier 1 verifier.

Core properties: parameter-binding, single-use enforcement, HMAC
signature verification, expiry. If any of these regress, the Tier 1
security contract breaks.
"""
import time

import pytest

from actionauth.authority import (
    CredentialDrift,
    CredentialExpired,
    CredentialReplay,
    InProcessAuthority,
    MalformedCredential,
    PayloadDriftAtMint,
    SignatureMismatch,
    SignatureReplay,
    sign_authorization_details,
)


SECRET = "test-shared-secret-32bytes-minimum-pad"
RAR_TYPE = "tasktracker_task_action"


@pytest.fixture
def authority():
    return InProcessAuthority(secret=SECRET, expected_rar_type=RAR_TYPE)


def _signed(command="delete-task", args=None, secret=SECRET, binding_message="Delete task t-42?"):
    return sign_authorization_details(
        command=command,
        args=args or {"task_id": "t-42"},
        rar_type=RAR_TYPE,
        approver_id="alice",
        binding_message=binding_message,
        secret=secret,
    )


# ── mint ──────────────────────────────────────────────────────────────────────


def test_mint_then_consume_happy_path(authority):
    signed = _signed()
    minted = authority.mint(signed)
    assert minted.command == "delete-task"
    assert minted.args == {"task_id": "t-42"}
    consumed = authority.consume(minted.credential, "delete-task", {"task_id": "t-42"})
    assert consumed.jti == minted.jti


def test_mint_rejects_bad_signature(authority):
    signed = _signed(secret="wrong-secret-16bytes-minimum")
    with pytest.raises(SignatureMismatch):
        authority.mint(signed)


def test_mint_rejects_unexpected_rar_type():
    authority = InProcessAuthority(secret=SECRET, expected_rar_type="some_other_type")
    signed = _signed()
    with pytest.raises(PayloadDriftAtMint):
        authority.mint(signed)


def test_mint_rejects_signature_replay(authority):
    """Consent Atomicity at Tier 1: one signed payload mints at most one
    credential. A second presentation of the same signed payload raises
    SignatureReplay rather than producing a fresh credential with a new
    jti."""
    signed = _signed()
    authority.mint(signed)
    with pytest.raises(SignatureReplay):
        authority.mint(signed)


# ── consume: single-use ─────────────────────────────────────────────────────


def test_consume_rejects_replay(authority):
    """*** The single-use property in test form. ***"""
    signed = _signed()
    minted = authority.mint(signed)
    authority.consume(minted.credential, "delete-task", {"task_id": "t-42"})
    with pytest.raises(CredentialReplay):
        authority.consume(minted.credential, "delete-task", {"task_id": "t-42"})


# ── consume: parameter binding ──────────────────────────────────────────────


def test_consume_rejects_drifted_args(authority):
    signed = _signed(args={"task_id": "approved"})
    minted = authority.mint(signed)
    with pytest.raises(CredentialDrift):
        authority.consume(minted.credential, "delete-task", {"task_id": "drifted"})


def test_consume_rejects_drifted_command(authority):
    signed = _signed(command="delete-task")
    minted = authority.mint(signed)
    with pytest.raises(CredentialDrift):
        authority.consume(minted.credential, "update-task", {"task_id": "t-42"})


# ── consume: malformed ──────────────────────────────────────────────────────


def test_consume_rejects_unknown_credential(authority):
    """Well-formed but the jti was never issued — that's a signature/identity
    failure (someone presented a credential we did not produce)."""
    with pytest.raises(SignatureMismatch):
        authority.consume("nonsense.abcdef", "delete-task", {"task_id": "t-42"})


def test_consume_rejects_malformed(authority):
    """No dot at all — not even structurally a credential. Distinct from
    a signature failure: nothing to verify against."""
    with pytest.raises(MalformedCredential):
        authority.consume("not-a-credential-at-all", "delete-task", {})


# ── consume: expiry ─────────────────────────────────────────────────────────


def test_consume_rejects_expired(authority, monkeypatch):
    signed = sign_authorization_details(
        command="delete-task",
        args={"task_id": "t-42"},
        rar_type=RAR_TYPE,
        approver_id="alice",
        binding_message="Delete task t-42?",
        secret=SECRET,
        ttl_seconds=1,
    )
    minted = authority.mint(signed)
    # Pretend we're 10 seconds in the future.
    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() + 10)
    with pytest.raises(CredentialExpired):
        authority.consume(minted.credential, "delete-task", {"task_id": "t-42"})
