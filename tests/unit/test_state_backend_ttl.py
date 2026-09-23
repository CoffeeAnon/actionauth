"""Durable replay-state TTL windows and explicit-purge semantics.

Companion to ``test_durable_state.py`` (which covers single-shot claims,
cross-connection sharing, cross-process replicas, restart durability, and
thread atomicity). This file pins the *time* dimension of the
``StateBackend`` contract:

  - records carry ``expired_at`` and issuance records (``get_issued``) are
    only visible while the window is open;
  - the single-use claims themselves are permanent ("once exchanged,
    always a replay") regardless of the window — the window exists for
    purge housekeeping, not for re-opening a replay;
  - ``purge_expired`` is explicit-only: it deletes closed windows and
    never runs automatically, so a consumer that skips the manual purge
    keeps blocking replays indefinitely;
  - clock injection drives all window decisions (no sleeping in tests);
  - the in-memory backend implements the same contract structurally.

The boundary that must never flip: a purge may drop the *record*, but a
re-presentation of a closed window is rejected by the consumer's own
expiry check before it ever consults the record — so purging changes no
security decision (see the module docstring of
``actionauth/authority/durable_state.py``).
"""
from __future__ import annotations

import hashlib
import hmac
import time

import pytest

from actionauth.authority import (
    DurableReplayState,
    InMemoryStateBackend,
    InProcessAuthority,
    OAuthAuthority,
    CredentialExpired,
    SignatureReplay,
    SignedAuthorizationDetails,
    sign_authorization_details,
)
from actionauth.authority.in_process import canonical_authorization_bytes

USER_SECRET = "ttl-test-user-secret-32bytes-padded"
MINT_SECRET = "ttl-test-mint-secret-32bytes-padded"
RAR_TYPE = "tasktracker_task_action"


class _Clock:
    """Injectable clock: tests advance time without sleeping.

    Starts at the *real* wall clock so that records whose ``expired_at``
    was computed from real time (by the signers / delegation authorities, which use
    ``time.time()`` directly) sit inside the backend's window logic."""

    def __init__(self, start: float | None = None) -> None:
        self.now = float(time.time() if start is None else start)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _signed(command: str = "delete-task", args: dict | None = None,
            ttl_seconds: int = 300, approver_id: str = "alice",
            binding_message: str = "Delete task t-42?"):
    return sign_authorization_details(
        command=command,
        args=args if args is not None else {"task_id": "t-42"},
        rar_type=RAR_TYPE,
        approver_id=approver_id,
        binding_message=binding_message,
        secret=USER_SECRET,
        ttl_seconds=ttl_seconds,
    )


# ── 1: claims are permanent; the window never re-opens a replay ────────────


def test_claimed_signature_stays_blocked_beyond_window(tmp_path) -> None:
    """``is_signature_consumed`` and the claim stay True past the window —
    the record's ``expired_at`` is only purge housekeeping."""
    clock = _Clock()
    state = DurableReplayState(str(tmp_path / "permanent.db"), clock=clock)

    signed = _signed()
    sig_hash = "sha256-of-canonical-bytes-under-test"

    assert state.claim_signature(sig_hash, expired_at=float(signed.exp)) is True
    assert state.claim_signature(sig_hash, expired_at=float(signed.exp)) is False
    assert state.is_signature_consumed(sig_hash) is True

    clock.advance(10_000)  # far past the 300s window
    # The record still blocks: no automatic expiry of the replay decision.
    assert state.is_signature_consumed(sig_hash) is True
    assert state.claim_signature(sig_hash, expired_at=float(signed.exp)) is False


def _stale_signed(exp: int) -> SignedAuthorizationDetails:
    """A correctly-HMAC'd payload with an explicit (already-past) ``exp`` —
    the signer helper always uses the wall clock, so a closed-window payload
    must be constructed by hand to be byte-stable."""
    command, args = "delete-task", {"task_id": "t-42"}
    payload_bytes = canonical_authorization_bytes(
        command, args, RAR_TYPE, exp, "alice", "Delete task t-42?",
    )
    signature = hmac.new(
        USER_SECRET.encode(), payload_bytes, hashlib.sha256,
    ).hexdigest()
    return SignedAuthorizationDetails(
        command=command, args=args, rar_type=RAR_TYPE, exp=exp,
        approver_id="alice", binding_message="Delete task t-42?",
        signature=signature,
    )


def test_purging_freed_key_but_consumer_still_rejects_expired_payload(tmp_path) -> None:
    """The boundary that must never flip: for a payload whose window has
    closed, the rejection comes from the consumer's own exp check — which
    runs BEFORE the backend claim — never from a backend record (purged or
    not) and never from a silent success."""
    clock = _Clock()
    state = DurableReplayState(str(tmp_path / "purge-exp.db"), clock=clock)
    authority = InProcessAuthority(secret=USER_SECRET, durable_state=state)

    stale = _stale_signed(exp=int(time.time()) - 10)

    # The delegation authority's mint exp-check fires first: CredentialExpired, not
    # SignatureReplay, not a fresh credential.
    with pytest.raises(CredentialExpired):
        authority.mint(stale)

    # And the rejection did not depend on backend state: the claim never
    # ran, so no record was ever created (and none needs purging).
    canonical = canonical_authorization_bytes(
        stale.command, stale.args, stale.rar_type, stale.exp,
        stale.approver_id, stale.binding_message,
    )
    assert not state.is_signature_consumed(hashlib.sha256(canonical).hexdigest())


# ── 2: get_issued is window-scoped; set_issued is single-writer ────────────


def test_issued_record_visible_only_while_window_open(tmp_path) -> None:
    clock = _Clock()
    state = DurableReplayState(str(tmp_path / "issued.db"), clock=clock)

    exp = int(clock()) + 60
    assert state.set_issued(
        "jti-1", command="delete-task", args={"task_id": "t-42"},
        exp=exp, expired_at=float(exp),
    ) is True
    # Double-write is a no-op (concurrent double-mint guard).
    assert state.set_issued(
        "jti-1", command="delete-task", args={"task_id": "t-42"},
        exp=exp, expired_at=float(exp),
    ) is False

    record = state.get_issued("jti-1")
    assert record is not None
    assert record[0] == "delete-task"
    assert record[1] == {"task_id": "t-42"}
    assert record[2] == exp

    # After the window closes the issuance record is invisible: the
    # credential is already expired, so no live consume can consult it.
    clock.advance(61)
    assert state.get_issued("jti-1") is None


# ── 3: restart within the window — replica B on the same file ──────────────


def test_durable_backend_survives_restart_within_window(tmp_path) -> None:
    """Replica B boots fresh on the same file *inside* the TTL: the
    re-mint is rejected (signature claim survived) and the already-
    consumed credential is rejected (jti claim survived)."""
    path = str(tmp_path / "restart-window.db")
    clock = _Clock()

    signed = _signed(command="update-task",
                     args={"task_id": "t-7", "title": "ship it"},
                     approver_id="bob", binding_message="Update task t-7?")

    replica_a = OAuthAuthority(
        user_signing_secret=USER_SECRET, mint_secret=MINT_SECRET,
        issuer="https://authority.reference.invalid", audience="bridge-resource-server",
        expected_rar_type=RAR_TYPE, durable_state=DurableReplayState(path, clock=clock),
    )
    minted = replica_a.mint(signed)
    replica_a.consume(minted.credential, "update-task",
                      {"task_id": "t-7", "title": "ship it"})
    # (Replica A is torn down — only the on-disk record remains.)

    replica_b = OAuthAuthority(
        user_signing_secret=USER_SECRET, mint_secret=MINT_SECRET,
        issuer="https://authority.reference.invalid", audience="bridge-resource-server",
        expected_rar_type=RAR_TYPE, durable_state=DurableReplayState(path, clock=clock),
    )
    with pytest.raises(SignatureReplay):
        replica_b.mint(signed)
    with pytest.raises(Exception) as excinfo:
        replica_b.consume(minted.credential, "update-task",
                          {"task_id": "t-7", "title": "ship it"})
    assert "already consumed" in str(excinfo.value)


# ── 4: purge is explicit, idempotent, and window-selective ─────────────────


def test_purge_expired_only_deletes_closed_windows(tmp_path) -> None:
    clock = _Clock()
    state = DurableReplayState(str(tmp_path / "purge.db"), clock=clock)

    now = clock()
    state.claim_signature("sig-old", expired_at=now + 10)
    state.claim_signature("sig-new", expired_at=now + 1000)
    state.claim_jti("jti-old", expired_at=now + 10)
    state.claim_jti("jti-new", expired_at=now + 1000)

    # Nothing is closed yet: an explicit purge right now deletes nothing.
    assert state.purge_expired() == 0

    clock.advance(11)  # close the 10s windows, keep the 1000s ones open
    assert state.purge_expired() == 2
    assert state.is_signature_consumed("sig-old") is False
    assert state.is_signature_consumed("sig-new") is True
    assert state.is_jti_consumed("jti-old") is False
    assert state.is_jti_consumed("jti-new") is True

    # Second purge at the same instant is a no-op (idempotent housekeeping).
    assert state.purge_expired() == 0

    clock.advance(1000)
    assert state.purge_expired() == 2
    assert state.purge_expired() == 0


# ── 5: in-memory backend mirrors the durable contract on the same clock ────


def test_in_memory_backend_same_window_semantics() -> None:
    clock = _Clock()
    state = InMemoryStateBackend(clock=clock)

    now = clock()
    state.claim_signature("sig-a", expired_at=now + 5)
    state.claim_jti("jti-a", expired_at=now + 5)
    state.claim_signature("sig-b", expired_at=now + 50)

    assert state.purge_expired() == 0
    clock.advance(6)
    assert state.purge_expired() == 2  # only the two 5s records
    assert state.is_signature_consumed("sig-a") is False
    assert state.is_signature_consumed("sig-b") is True
    assert state.is_jti_consumed("jti-a") is False
    assert state.is_jti_consumed("jti-b") is False

    # A delegation authority built on the in-memory backend sees the same replay
    # contract for a payload whose record was NOT purged.
    fresh_clock = _Clock()
    shared = InMemoryStateBackend(clock=fresh_clock)
    authority = InProcessAuthority(secret=USER_SECRET, durable_state=shared)
    s2 = _signed(ttl_seconds=300)
    authority.mint(s2)
    with pytest.raises(SignatureReplay):
        authority.mint(s2)


# ── 6: jti_namespace isolation with a shared durable backend ───────────────


def test_jti_namespace_keeps_authority_and_rs_tables_independent(tmp_path) -> None:
    """The three-layer architecture requires the RS's consumed-jti state to
    be independent of the delegation authority's even when they share one durable backend:
    the namespace prefix on the jti key is what provides that independence."""
    clock = _Clock()
    state = DurableReplayState(str(tmp_path / "ns.db"), clock=clock)

    authority = InProcessAuthority(secret=USER_SECRET, durable_state=state, jti_namespace="authority")
    signed = _signed(args={"task_id": "t-9"}, binding_message="Delete task t-9?")
    minted = authority.mint(signed)
    authority.consume(minted.credential, "delete-task", {"task_id": "t-9"})

    # The authority namespaced the key: the raw jti is NOT marked consumed, so
    # an RS on the same backend (namespace "rs") does not see the authority's
    # consume as its own.
    assert state.is_jti_consumed(minted.jti) is False
    assert state.is_jti_consumed(f"authority:{minted.jti}") is True
