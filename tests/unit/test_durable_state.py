"""Durable shared replay state — the cross-replica / restart single-use guard.

These tests are the load-bearing proof for card item #1: one-approval /
one-execution must hold *across replicas and across a restart*, not just
within a single process. The boundary being crossed is a **real second
SQLite connection to a real temp file** — there is no mock of the function
under test; two ``DurableReplayState`` objects (or two delegation authority / RS instances)
genuinely share the same on-disk rows, which is the same mechanism a
production deployment uses when several replicas open one file on shared
storage.

The in-memory baseline (``_consumed_signatures`` / ``_consumed`` sets) is
*not* shared across processes and vanishes on restart. The durable store is
what closes that surface. Every assertion below is chosen so that if the
shared-state wiring regresses (e.g. a future worker drops the injected state
or reverts a surface to its local set), the test fails.
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import threading
import time

import pytest

from actionauth.authority import (
    CredentialDrift,
    CredentialExpired,
    CredentialReplay,
    DurableReplayState,
    InProcessAuthority,
    OAuthAuthority,
    PayloadDriftAtMint,
    SignatureMismatch,
    SignatureReplay,
    sign_authorization_details,
)

# ── shared test constants ────────────────────────────────────────────────────

SECRET = "shared-hmac-secret-32bytes-padding!"
USER_SECRET = "user-side-signing-secret-32bytes-pad"
MINT_SECRET = "authority-mint-secret-32bytes-padding-x"
RAR_TYPE = "tasktracker_task_action"
ISSUER = "https://authority.reference.invalid"
AUDIENCE = "bridge-resource-server"
TTL = 300


def _inproc_signed(command="delete-task", args=None, **kw):
    return sign_authorization_details(
        command=command,
        args=args or {"task_id": "t-42"},
        rar_type=RAR_TYPE,
        approver_id="alice",
        binding_message=kw.pop("binding_message", "Delete task t-42?"),
        secret=kw.pop("secret", SECRET),
        ttl_seconds=kw.pop("ttl_seconds", TTL),
    )


def _oauth_signed(command="delete-task", args=None, **kw):
    return sign_authorization_details(
        command=command,
        args=args or {"task_id": "t-42"},
        rar_type=RAR_TYPE,
        approver_id="alice",
        binding_message=kw.pop("binding_message", "Delete task t-42?"),
        secret=kw.pop("secret", USER_SECRET),
        ttl_seconds=kw.pop("ttl_seconds", TTL),
    )


def _authority_a_b(path):
    """Two independent delegation authorities over one shared durable file (two replicas)."""
    va = InProcessAuthority(secret=SECRET, durable_state=DurableReplayState(str(path)))
    vb = InProcessAuthority(secret=SECRET, durable_state=DurableReplayState(str(path)))
    return va, vb


# ── 1-2: claim_signature single-shot + is_signature_consumed ────────────────


def test_claim_signature_is_single_shot(tmp_path):
    state = DurableReplayState(str(tmp_path / "s.db"))
    h = "sighash-abc"
    assert state.claim_signature(h, expired_at=time.time() + 60) is True
    # Re-presentation — within the window and after it — is always a replay.
    assert state.claim_signature(h, expired_at=time.time() + 60) is False
    assert state.claim_signature(h, expired_at=time.time() - 5) is False
    # is_* mirrors the claim.
    assert state.is_signature_consumed(h) is True
    assert state.is_signature_consumed("never-seen") is False
    state.close()


# ── 3: claim_jti single-shot; re-claim after the window only via purge ──────


def test_claim_jti_single_shot_and_purge_reopens_window(tmp_path):
    now = [1000.0]
    state = DurableReplayState(str(tmp_path / "j.db"), clock=lambda: now[0])
    assert state.claim_jti("jti-1", expired_at=1100.0) is True
    # Immediate re-consume is a replay (within the window).
    assert state.claim_jti("jti-1", expired_at=1100.0) is False
    # The record is *permanent*: even after the window closes the record
    # still blocks. (jti is single-use by definition; this is the safe
    # direction, so a re-claim after expiry is deliberately refused.)
    now[0] = 2000.0
    assert state.is_jti_consumed("jti-1") is True
    assert state.claim_jti("jti-1", expired_at=1100.0) is False
    # Operator housekeeping reopens the window: purge drops closed rows and a
    # (new) presentation no longer collides with a purged key.
    assert state.purge_expired() == 1
    assert state.is_jti_consumed("jti-1") is False
    assert state.claim_jti("jti-1", expired_at=2100.0) is True
    state.close()


# ── 4: two connections, one file (the genuine cross-process boundary) ───────


def test_two_connections_one_file_share_state(tmp_path):
    path = str(tmp_path / "shared.db")
    a = DurableReplayState(path)
    b = DurableReplayState(path)  # a *second* connection to the *same* file
    a.claim_signature("sig-A", expired_at=time.time() + 60)
    a.claim_jti("jti-A", expired_at=time.time() + 60)
    # B sees A's records — this is the cross-process sharing guarantee.
    assert b.is_signature_consumed("sig-A") is True
    assert b.claim_signature("sig-A", expired_at=time.time() + 60) is False
    assert b.is_jti_consumed("jti-A") is True
    assert b.claim_jti("jti-A", expired_at=time.time() + 60) is False
    a.close()
    b.close()


# ── 4b: genuine two-OS-process cross-replica (strongest boundary) ───────────
#
# The two-connection test above shares one process. A real deployment is two
# OS processes (replicas) over one file on shared storage. This spawns a real
# child `python` process that opens the same SQLite file and attempts to
# re-mint the same signed payload / re-consume the same jti. If the shared
# state wiring regresses, the child will succeed where it must fail.


_CHILD_SCRIPT = r'''
import os, sys, json
from actionauth.authority import DurableReplayState, OAuthAuthority
from actionauth.authority.interface import SignedAuthorizationDetails
sd = SignedAuthorizationDetails(**json.loads(os.environ["DR_SIGNED"]))
authority = OAuthAuthority(
    user_signing_secret=os.environ["DR_USER_SECRET"],
    mint_secret=os.environ["DR_MINT_SECRET"],
    issuer="https://authority.reference.invalid", audience="bridge-resource-server",
    durable_state=DurableReplayState(os.environ["DR_PATH"]),
)
try:
    minted = authority.mint(sd)
    # If the mint succeeded (a second credential from the same signature),
    # also consume it — proving the whole approval executed a second time.
    authority.consume(minted.credential, sd.command, sd.args)
    print(json.dumps({"second_execution": True, "minted": True}))
except Exception as e:  # noqa: BLE001 — the child reports what happened
    print(json.dumps({"second_execution": False, "error": type(e).__name__}))
'''


def test_true_cross_process_replica_cannot_reexecute(tmp_path):
    path = str(tmp_path / "xproc.db")
    # Parent = replica A: mint + consume the one approval, recording it.
    parent = OAuthAuthority(
        user_signing_secret=USER_SECRET, mint_secret=MINT_SECRET,
        issuer=ISSUER, audience=AUDIENCE, durable_state=DurableReplayState(path),
    )
    signed = _oauth_signed()
    cred = parent.mint(signed)
    parent.consume(cred.credential, "delete-task", {"task_id": "t-42"})

    # Child = replica B (a separate OS process): tries the SAME approval.
    env = {
        **os.environ,
        "DR_PATH": path,
        "DR_USER_SECRET": USER_SECRET,
        "DR_MINT_SECRET": MINT_SECRET,
        "DR_SIGNED": json.dumps(signed.__dict__),
    }
    proc = subprocess.run(
        [sys.executable, "-c", _CHILD_SCRIPT],
        capture_output=True, text=True, cwd=os.getcwd(), env=env, timeout=60,
    )
    out = json.loads(proc.stdout.strip().splitlines()[-1])
    # The second execution MUST NOT happen on a different process.
    assert out["second_execution"] is False, out
    assert out["error"] == "SignatureReplay", out
    assert proc.returncode == 0, proc.stderr


# ── 5: cross-replica signature replay (the card's #1 known trap) ────────────


def test_cross_replica_signature_replay_inprocess(tmp_path):
    va, vb = _authority_a_b(tmp_path / "ip.db")
    signed = _inproc_signed()
    mint_a = va.mint(signed)  # replica A exchanges the signature
    # The *same* signed payload presented to replica B must not mint again.
    with pytest.raises(SignatureReplay):
        vb.mint(signed)
    # A fresh, independently-signed payload still mints on B (we didn't over-
    # block distinct approvals — only replay of the identical bytes).
    mint_b = vb.mint(_inproc_signed(args={"task_id": "t-99"}))
    assert mint_a.credential != mint_b.credential


def test_same_signature_rejected_across_replicas(tmp_path):
    """Cross-replica replay at the authority layer: two
    ``InProcessAuthority`` replicas sharing ONE ``DurableReplayState``.
    Replica A mints a signed payload → success. Replica B mints the
    *same* signed payload → ``SignatureReplay``. The signature-consumed
    table, not per-process state, is the authority."""
    va, vb = _authority_a_b(tmp_path / "replica.db")
    signed = _inproc_signed()
    # Replica A: first presentation of the signature — mints fine.
    cred_a = va.mint(signed)
    assert cred_a.credential
    # Replica B, same durable file: the identical signature is already
    # consumed → replay, no second credential.
    with pytest.raises(SignatureReplay):
        vb.mint(signed)


def test_cross_replica_oauth_mint_and_consume(tmp_path):
    path = str(tmp_path / "o.db")
    va = OAuthAuthority(
        user_signing_secret=USER_SECRET, mint_secret=MINT_SECRET,
        issuer=ISSUER, audience=AUDIENCE, durable_state=DurableReplayState(path),
    )
    vb = OAuthAuthority(
        user_signing_secret=USER_SECRET, mint_secret=MINT_SECRET,
        issuer=ISSUER, audience=AUDIENCE, durable_state=DurableReplayState(path),
    )
    signed = _oauth_signed()
    # Same signed payload re-presented on replica B → SignatureReplay.
    mint_a = va.mint(signed)
    with pytest.raises(SignatureReplay):
        vb.mint(signed)
    # Consume the minted JWT on replica A; the *same* JWT on replica B →
    # CredentialReplay. This is the Tier-2 self-contained-JWT cross-replica
    # consume guarantee.
    va.consume(mint_a.credential, "delete-task", {"task_id": "t-42"})
    with pytest.raises(CredentialReplay):
        vb.consume(mint_a.credential, "delete-task", {"task_id": "t-42"})


# ── 6: the card's hardest test — one approval, one execution, two instances ─


def test_two_instances_same_approval_executes_once(tmp_path):
    """If a future regression let the same signed approval execute twice, this
    fails. Two independent OAuthAuthority replicas share one durable store; the
    second full attempt (re-present the *same* signed payload) must not
    produce a second consumable credential.
    """
    path = str(tmp_path / "hard.db")
    va = OAuthAuthority(
        user_signing_secret=USER_SECRET, mint_secret=MINT_SECRET,
        issuer=ISSUER, audience=AUDIENCE, durable_state=DurableReplayState(path),
    )
    vb = OAuthAuthority(
        user_signing_secret=USER_SECRET, mint_secret=MINT_SECRET,
        issuer=ISSUER, audience=AUDIENCE, durable_state=DurableReplayState(path),
    )
    signed = _oauth_signed()

    # First approval: mint + execute. Succeeds exactly once.
    c1 = va.mint(signed)
    va.consume(c1.credential, "delete-task", {"task_id": "t-42"})

    # Second full attempt with the *identical* signed approval: no second
    # credential can be minted from it, on either replica.
    with pytest.raises(SignatureReplay):
        va.mint(signed)
    with pytest.raises(SignatureReplay):
        vb.mint(signed)

    # And the one credential already issued cannot be re-consumed anywhere.
    with pytest.raises(CredentialReplay):
        va.consume(c1.credential, "delete-task", {"task_id": "t-42"})
    with pytest.raises(CredentialReplay):
        vb.consume(c1.credential, "delete-task", {"task_id": "t-42"})


# ── 7: restart durability (record survives a fresh process on the same file) ─


def test_restart_durability_oauth(tmp_path):
    path = str(tmp_path / "restart.db")

    signed = _oauth_signed()
    # "Replica A" mints + consumes, then is torn down (restart).
    a = OAuthAuthority(
        user_signing_secret=USER_SECRET, mint_secret=MINT_SECRET,
        issuer=ISSUER, audience=AUDIENCE, durable_state=DurableReplayState(path),
    )
    c = a.mint(signed)
    a.consume(c.credential, "delete-task", {"task_id": "t-42"})
    del a  # process A gone; only the on-disk record remains.

    # "Replica B" boots fresh on the same file. The consumed record survives.
    b = OAuthAuthority(
        user_signing_secret=USER_SECRET, mint_secret=MINT_SECRET,
        issuer=ISSUER, audience=AUDIENCE, durable_state=DurableReplayState(path),
    )
    # The previously-minted credential is still rejected (consume record).
    with pytest.raises(CredentialReplay):
        b.consume(c.credential, "delete-task", {"task_id": "t-42"})
    # And the signed payload still cannot be re-minted (mint record).
    with pytest.raises(SignatureReplay):
        b.mint(signed)


# ── 8: atomicity under concurrency (N threads, one shared state) ────────────


def test_atomicity_one_winner_among_many_threads(tmp_path):
    path = str(tmp_path / "concurrent.db")
    state = DurableReplayState(path)
    sig_results = []
    jti_results = []
    barrier = threading.Barrier(16)

    def sig_worker():
        barrier.wait()
        sig_results.append(state.claim_signature("one-sig", expired_at=time.time() + 60))

    def jti_worker():
        barrier.wait()
        jti_results.append(state.claim_jti("one-jti", expired_at=time.time() + 60))

    threads = [threading.Thread(target=sig_worker) for _ in range(8)]
    threads += [threading.Thread(target=jti_worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # Exactly one winner each, despite 8 concurrent claimers per key.
    assert sig_results.count(True) == 1, sig_results
    assert jti_results.count(True) == 1, jti_results
    state.close()


# ── 9: durable path did not swallow the existing security checks ────────────


def test_durable_preserves_binding_and_exception_surface(tmp_path):
    path = str(tmp_path / "bind.db")
    state = DurableReplayState(path)
    va = InProcessAuthority(secret=SECRET, durable_state=state)

    signed = _inproc_signed()
    c = va.mint(signed)

    # Parameter drift at consume still raises CredentialDrift (not replay, not
    # success) — durable state did not swallow the binding check.
    with pytest.raises(CredentialDrift):
        va.consume(c.credential, "delete-task", {"task_id": "WRONG"})
    # The drift attempt did NOT consume the credential (claim happens only on
    # a fully-valid consume), so the correct consume still succeeds.
    ok = va.consume(c.credential, "delete-task", {"task_id": "t-42"})
    assert ok.jti == c.jti
    # Now it's genuinely consumed.
    with pytest.raises(CredentialReplay):
        va.consume(c.credential, "delete-task", {"task_id": "t-42"})


def test_durable_preserves_expanded_rartype_and_expiration_at_mint(tmp_path):
    path = str(tmp_path / "mint.db")
    state = DurableReplayState(path)
    va = InProcessAuthority(
        secret=SECRET, expected_rar_type=RAR_TYPE, durable_state=state,
    )
    # Wrong rar_type is rejected at mint (durable path must not skip this).
    wrong_rar = sign_authorization_details(
        command="delete-task", args={"task_id": "t-42"}, rar_type="some_other_rar",
        approver_id="alice", binding_message="Delete task t-42?", secret=SECRET,
    )
    with pytest.raises(PayloadDriftAtMint):
        va.mint(wrong_rar)
    # An already-expired signed payload is rejected before it ever claims a
    # signature record. The signature must be valid *for those exact bytes*
    # (including the past exp) so mint gets past the HMAC check and reaches the
    # exp-bounds check — i.e. we prove the exp guard fires, not the HMAC guard.
    import hashlib
    import hmac as _hmac
    from actionauth.authority.in_process import canonical_authorization_bytes
    from actionauth.authority.interface import SignedAuthorizationDetails

    past_exp = int(time.time()) - 10
    old_bytes = canonical_authorization_bytes(
        "delete-task", {"task_id": "t-42"}, RAR_TYPE, past_exp, "alice",
        "Delete task t-42?",
    )
    old_sig = _hmac.new(SECRET.encode(), old_bytes, hashlib.sha256).hexdigest()
    old = SignedAuthorizationDetails(
        command="delete-task", args={"task_id": "t-42"}, rar_type=RAR_TYPE,
        exp=past_exp, approver_id="alice", binding_message="Delete task t-42?",
        signature=old_sig,
    )
    with pytest.raises(CredentialExpired):
        va.mint(old)
    # Nothing was recorded (invalid payloads don't poison the store).
    h = hashlib.sha256(old_bytes).hexdigest()
    assert state.is_signature_consumed(h) is False


# ── Resource Server cross-replica single-use ────────────────────────────────


def test_rs_two_instances_same_jwt_executes_once(tmp_path):
    """The Resource Server is the true consume point in the three-layer mode.
    Two RS replicas sharing one durable store: a JWT consumed on RS-A must be
    rejected on RS-B (CredentialReplay), and executed at most once overall.
    """
    from actionauth.core.client import InMemoryTaskStore
    from actionauth.rs.jwt_resource_server import JwtResourceServer, RsSuccess

    path = str(tmp_path / "rs.db")
    mint = OAuthAuthority(
        user_signing_secret=USER_SECRET, mint_secret=MINT_SECRET,
        issuer=ISSUER, audience=AUDIENCE,
    )
    client_a = InMemoryTaskStore()
    client_b = InMemoryTaskStore()
    rs_a = JwtResourceServer(
        verification_secret=MINT_SECRET, expected_issuer=ISSUER,
        expected_audience=AUDIENCE, client=client_a,
        durable_state=DurableReplayState(path),
    )
    rs_b = JwtResourceServer(
        verification_secret=MINT_SECRET, expected_issuer=ISSUER,
        expected_audience=AUDIENCE, client=client_b,
        durable_state=DurableReplayState(path),
    )
    # Mint a token bound to the command the RS will actually run (list-tasks,
    # no args) so the first execution passes the binding check.
    list_signed = sign_authorization_details(
        command="list-tasks", args={}, rar_type=RAR_TYPE,
        approver_id="alice", binding_message="List tasks?", secret=USER_SECRET,
    )
    token = mint.mint(list_signed).credential

    # First execution on RS-A succeeds.
    out_a = rs_a.execute("list-tasks", {}, token)
    assert isinstance(out_a, RsSuccess), out_a

    # The *same* JWT on RS-B is a replay — the RS is the load-bearing
    # cross-replica consume guard.
    out_b = rs_b.execute("list-tasks", {}, token)
    assert not isinstance(out_b, RsSuccess), out_b
    assert "Replay" in type(out_b).__name__ or "Replay" in str(out_b), out_b

    # Re-execution on RS-A is likewise a replay.
    out_a2 = rs_a.execute("list-tasks", {}, token)
    assert not isinstance(out_a2, RsSuccess), out_a2


# ── construction / packaging sanity ──────────────────────────────────────────


def test_package_reexport_and_conn_backed_construction(tmp_path):
    # `from actionauth.authority import DurableReplayState` (the documented import).
    assert callable(DurableReplayState)
    # A caller-supplied connection is shared (single in-memory DB, one process)
    # and not closed by DurableReplayState.close().
    conn = sqlite3.connect(":memory:")
    s = DurableReplayState(conn)
    s.claim_signature("x", expired_at=time.time() + 5)
    s.close()
    # The caller still owns the connection — it works after close().
    assert conn.execute(
        "SELECT 1 FROM consumed_signatures WHERE sig_hash=?", ("x",)
    ).fetchone() is not None
