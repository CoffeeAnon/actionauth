"""Durable consent store: TTL window, single-winner CAS, restart durability.

Companion to the in-memory consent tests. The durable store
(``actionauth.consent.durable_consent.DurableConsentStore``) is the shared
SQLite substrate that makes a URL-mode consent session survive bridge
restarts and stay consistent across replicas. The contract under test:

  - a session is valid for ``ttl_seconds`` from ``created_at``; an expired
    session is treated as if it never existed — ``get`` returns ``None``
    and the submit/deny CAS fails, so a stale session can never be
    approved after the fact;
  - exactly ONE submit wins and exactly ONE deny wins (the database CAS
    is the authority, not a check-then-set); a later conflicting
    transition is a no-op returning ``False``;
  - terminal rows (submitted/denied) survive restarts on the same file —
    a second replica reads the approval; pending rows also survive while
    inside their window, so the approval can be completed on a different
    process than the one that opened the consent page;
  - ``purge_expired`` is explicit-only and touches *pending* rows only:
    terminal rows are the human's audit trail and are never reclaimed;
  - the whole single-agent HITL flow (McpHitlGate + durable store +
    delegation authority) works end to end, and a restarted replica sharing the durable
    replay state still refuses to re-mint an already-exchanged payload.

Clock injection drives every window decision — no sleeping in tests.
"""
from __future__ import annotations

import hashlib
import threading
import time

import pytest

pytest.importorskip("mcp")

from mcp import types as mcp_types  # noqa: E402

from actionauth.consent.demo_signer import demo_sign_as_user  # noqa: E402
from actionauth.consent.durable_consent import DurableConsentStore  # noqa: E402
from actionauth.mcp.hitl import McpHitlGate, consent_session_id  # noqa: E402
from actionauth.authority import (  # noqa: E402
    DurableReplayState,
    InProcessAuthority,
    SignatureReplay,
)
from actionauth.authority.in_process import canonical_authorization_bytes  # noqa: E402

USER_SECRET = "durable-consent-user-secret-32bytes-min"
RAR_TYPE = "tasktracker_task_action"


class _Clock:
    """Injected clock: starts at the real wall clock (so any record
    created with the default clock also sits inside the window logic) and
    advances without sleeping."""

    def __init__(self, start: float | None = None) -> None:
        self.now = float(time.time() if start is None else start)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _store(tmp_path, *, clock: _Clock | None = None, ttl: float = 300.0):
    return DurableConsentStore(
        str(tmp_path / "consent.db"), ttl_seconds=ttl, clock=clock or _Clock(),
    )


def _action_overrides(**kw) -> dict:
    base = dict(
        command="delete-task",
        args={"task_id": "t-42"},
        rar_type=RAR_TYPE,
        approver_id="alice",
        binding_message="Delete task t-42?",
    )
    base.update(kw)
    return base


def _signed(**kw) -> dict:
    overrides = _action_overrides(**kw)
    return demo_sign_as_user(user_secret=USER_SECRET, **overrides)


# ── 1: session lifecycle and the TTL window ────────────────────────────────


def test_created_session_is_visible_until_the_window_closes(tmp_path) -> None:
    clock = _Clock()
    store = _store(tmp_path, clock=clock, ttl=300.0)

    req = store.create(**_action_overrides())
    sid = req.session_id
    created_at = req.action.created_at
    # The store stamped created_at from the injected clock, and the window
    # is exactly ttl_seconds wide.
    assert abs(created_at - clock()) < 1.0

    got = store.get(sid)
    assert got is not None
    assert got.command == "delete-task"
    assert dict(got.args) == {"task_id": "t-42"}
    assert got.signed_payload is None
    assert got.denied is False

    # Just inside the window: still visible.
    clock.advance(299)
    assert store.get(sid) is not None

    # Window closed: the session is treated as if it never existed.
    clock.advance(2)
    assert store.get(sid) is None
    # And an expired session can never be approved after the fact.
    assert store.submit_signed(sid, _signed()) is False
    assert store.deny(sid) is False


def test_get_of_unknown_session_is_none(tmp_path) -> None:
    store = _store(tmp_path)
    assert store.get("mcp-does-not-exist") is None


# ── 2: single-winner CAS — submit vs submit, submit vs deny ────────────────


def test_exactly_one_submit_wins_among_contenders(tmp_path) -> None:
    clock = _Clock()
    store = _store(tmp_path, clock=clock)
    sid = store.create(**_action_overrides(),
                       session_id="mcp-test-sid").session_id

    winner: list[bool] = []
    lock = threading.Lock()

    def submit() -> None:
        result = store.submit_signed(sid, _signed())
        with lock:
            winner.append(result)

    threads = [threading.Thread(target=submit) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert winner.count(True) == 1
    # The winner's payload is what the store carries.
    req = store.get(sid)
    assert req is not None
    assert req.signed_payload is not None
    assert req.signed_payload["command"] == "delete-task"
    assert req.denied is False


def test_deny_after_submit_is_noop_and_submitted_row_is_kept(tmp_path) -> None:
    store = _store(tmp_path)
    sid = store.create(**_action_overrides(),
                       session_id="mcp-sd").session_id

    assert store.submit_signed(sid, _signed()) is True
    # A late deny cannot un-submit: the CAS requires status='pending'.
    assert store.deny(sid) is False
    req = store.get(sid)
    assert req is not None
    assert req.signed_payload is not None
    assert req.denied is False

    # And a second submit (even with different content) is a no-op: the
    # human signed what they saw, not a v2.
    assert store.submit_signed(
        sid,
        _signed(approver_id="mallory",
                binding_message="Delete task t-42? (v2)"),
    ) is False
    req = store.get(sid)
    assert req is not None
    assert req.signed_payload is not None
    assert req.signed_payload["approver_id"] == "alice"


def test_deny_wins_when_it_arrives_first(tmp_path) -> None:
    store = _store(tmp_path)
    sid = store.create(**_action_overrides(),
                       session_id="mcp-d").session_id

    assert store.deny(sid) is True
    assert store.deny(sid) is False            # second deny: no-op
    assert store.submit_signed(sid, _signed()) is False  # submit after deny: no-op
    req = store.get(sid)
    assert req is not None
    assert req.denied is True
    assert req.signed_payload is None


# ── 3: idempotent create (retried tools/call self-correlation) ─────────────


def test_create_is_idempotent_and_keeps_original_action(tmp_path) -> None:
    store = _store(tmp_path)
    sid = "mcp-retried"
    store.create(**_action_overrides(), session_id=sid)
    # A retry with a DIFFERENT binding message must not overwrite what the
    # human is being asked to sign: INSERT OR IGNORE keeps the original.
    second = store.create(
        command="delete-task", args={"task_id": "t-42"}, rar_type=RAR_TYPE,
        approver_id="alice", binding_message="Something different!",
        session_id=sid,
    )
    assert second.session_id == sid
    assert second.binding_message == "Delete task t-42?"
    assert second.command == "delete-task"


# ── 4: restart durability — terminal and in-window rows survive on the file ─


def test_submitted_row_survives_restart_and_is_readable_by_replica_b(tmp_path) -> None:
    path = str(tmp_path / "restart.db")
    clock = _Clock()

    a = DurableConsentStore(path, ttl_seconds=300.0, clock=clock)
    sid = a.create(**_action_overrides(),
                   session_id="mcp-restart").session_id
    assert a.submit_signed(sid, _signed()) is True
    a.close()  # process A is gone; only the file remains

    b = DurableConsentStore(path, ttl_seconds=300.0, clock=clock)
    req = b.get(sid)
    assert req is not None
    assert req.signed_payload is not None
    assert req.signed_payload["command"] == "delete-task"
    # The terminal row is not re-submittable or re-deniable by anyone.
    assert b.submit_signed(sid, _signed(approver_id="mallory")) is False
    assert b.deny(sid) is False
    b.close()


def test_pending_row_survives_restart_within_window(tmp_path) -> None:
    path = str(tmp_path / "pending-restart.db")
    clock = _Clock()

    a = DurableConsentStore(path, ttl_seconds=300.0, clock=clock)
    sid = a.create(**_action_overrides(),
                   session_id="mcp-pending").session_id
    a.close()  # bridge restarted mid-approval

    b = DurableConsentStore(path, ttl_seconds=300.0, clock=clock)
    assert b.get(sid) is not None
    # A different process can complete the approval the human started.
    assert b.submit_signed(sid, _signed()) is True
    req = b.get(sid)
    assert req is not None
    assert req.signed_payload is not None
    b.close()


def test_pending_row_past_ttl_cannot_be_completed_after_restart(tmp_path) -> None:
    path = str(tmp_path / "stale-restart.db")
    clock = _Clock()

    a = DurableConsentStore(path, ttl_seconds=300.0, clock=clock)
    sid = a.create(**_action_overrides(),
                   session_id="mcp-stale").session_id
    a.close()

    clock.advance(301)  # the human returns after the window has closed
    b = DurableConsentStore(path, ttl_seconds=300.0, clock=clock)
    assert b.get(sid) is None
    assert b.submit_signed(sid, _signed()) is False
    b.close()


# ── 5: purge is explicit, pending-only, idempotent ─────────────────────────


def test_purge_expired_reclaims_only_expired_pending_rows(tmp_path) -> None:
    clock = _Clock()
    store = _store(tmp_path, clock=clock, ttl=300.0)

    s_pend = store.create(**_action_overrides(),
                          session_id="mcp-pend").session_id
    s_sub = store.create(**_action_overrides(),
                         session_id="mcp-sub").session_id
    store.submit_signed(s_sub, _signed())
    s_deny = store.create(**_action_overrides(),
                          session_id="mcp-deny").session_id
    store.deny(s_deny)

    assert store.purge_expired() == 0  # nothing closed yet

    clock.advance(301)  # all four rows are now past their window
    purged = store.purge_expired()
    assert purged == 1  # ONLY the still-pending row was reclaimed
    assert store.get(s_pend) is None

    # Terminal rows are the human's audit trail: they were NOT purged.
    # (get() also filters on the window, so after the advance even a
    # surviving terminal row is invisible through get — assert on the
    # database directly instead: the rows must still be there, i.e. only
    # the pending row was deleted.)
    import sqlite3

    conn = sqlite3.connect(str(tmp_path / "consent.db"))
    rows = conn.execute(
        "SELECT session_id, status FROM consent_sessions ORDER BY session_id"
    ).fetchall()
    conn.close()
    # The pending row is gone; the two terminal rows are intact.
    assert (s_pend, "pending") not in rows
    assert (s_sub, "submitted") in rows
    assert (s_deny, "denied") in rows
    # And idempotent: nothing left to reclaim.
    assert store.purge_expired() == 0


# ── 6: the full single-agent HITL flow on the durable substrate ────────────


def _hitl(tmp_path, *, clock: _Clock | None = None):
    store = DurableConsentStore(
        str(tmp_path / "hitl.db"), ttl_seconds=300.0, clock=clock or _Clock(),
    )
    authority = InProcessAuthority(
        secret=USER_SECRET,
        durable_state=DurableReplayState(str(tmp_path / "replay.db")),
    )
    gate = McpHitlGate(
        consent_store=store,
        bridge_base_url="https://bridge.example",
        rar_type=RAR_TYPE,
        authority=authority,
    )
    return store, authority, gate


def test_hitl_gate_full_flow_with_durable_store(tmp_path) -> None:
    store, authority, gate = _hitl(tmp_path)

    params = gate.begin(
        command="delete-task", args={"task_id": "t-42"},
        caller_id="alice", binding_message="Delete task t-42?",
    )
    assert isinstance(params, mcp_types.ElicitRequestURLParams)
    sid = consent_session_id(
        caller_id="alice", command="delete-task", args={"task_id": "t-42"},
    )
    assert params.elicitation_id == sid
    assert params.url.endswith(f"/consent/{sid}")

    # No approval yet: resume is a no-op.
    assert gate.try_resume(
        command="delete-task", args={"task_id": "t-42"}, caller_id="alice",
    ) is None

    # The human approves at the consent surface (demo signer, server-side).
    signed = demo_sign_as_user(
        command="delete-task", args={"task_id": "t-42"}, rar_type=RAR_TYPE,
        approver_id="alice", binding_message="Delete task t-42?",
        user_secret=USER_SECRET,
    )
    assert store.submit_signed(sid, signed) is True

    token = gate.try_resume(
        command="delete-task", args={"task_id": "t-42"}, caller_id="alice",
    )
    assert token is not None
    consumed = authority.consume(token, "delete-task", {"task_id": "t-42"})
    assert consumed.command == "delete-task"

    # Idempotent resume: same token, no re-mint.
    assert gate.try_resume(
        command="delete-task", args={"task_id": "t-42"}, caller_id="alice",
    ) == token


def test_hitl_restart_replica_refuses_to_remint_shared_payload(tmp_path) -> None:
    """Replica A mints the credential from the shared consent store; the
    bridge restarts and replica B re-presents the same stored signed
    payload. A fresh in-process cache cannot be the replay authority —
    the durable signature state shared across replicas is. B's mint must
    fail with SignatureReplay, not hand out a second credential."""
    path = str(tmp_path / "hitl-restart.db")
    replay_path = str(tmp_path / "replay.db")
    clock = _Clock()

    store_a = DurableConsentStore(path, ttl_seconds=300.0, clock=clock)
    authority_a = InProcessAuthority(
        secret=USER_SECRET,
        durable_state=DurableReplayState(replay_path),
    )
    gate_a = McpHitlGate(consent_store=store_a,
                         bridge_base_url="https://bridge.example",
                         rar_type=RAR_TYPE, authority=authority_a)
    gate_a.begin(command="delete-task", args={"task_id": "t-42"},
                 caller_id="alice", binding_message="Delete task t-42?")
    sid = consent_session_id(caller_id="alice", command="delete-task",
                             args={"task_id": "t-42"})
    signed = demo_sign_as_user(
        command="delete-task", args={"task_id": "t-42"}, rar_type=RAR_TYPE,
        approver_id="alice", binding_message="Delete task t-42?",
        user_secret=USER_SECRET,
    )
    assert store_a.submit_signed(sid, signed) is True
    token_a = gate_a.try_resume(command="delete-task",
                                args={"task_id": "t-42"}, caller_id="alice")
    assert token_a is not None
    store_a.close()  # restart

    # Replica B: fresh process, fresh gate, fresh in-process cache — same
    # consent file and same durable replay state.
    store_b = DurableConsentStore(path, ttl_seconds=300.0, clock=clock)
    authority_b = InProcessAuthority(
        secret=USER_SECRET,
        durable_state=DurableReplayState(replay_path),
    )
    req = store_b.get(sid)
    assert req is not None
    assert req.signed_payload is not None
    # Structural sanity: the stored payload is byte-stable (the same
    # canonical bytes would produce the same signature hash A already
    # exchanged).
    import hmac

    canonical = canonical_authorization_bytes(
        req.signed_payload["command"], req.signed_payload["args"],
        req.signed_payload["rar_type"], req.signed_payload["exp"],
        req.signed_payload["approver_id"],
        req.signed_payload["binding_message"],
    )
    expected_sig = hmac.new(
        USER_SECRET.encode(), canonical, hashlib.sha256,
    ).hexdigest()
    assert expected_sig == signed["signature"]

    # Re-presenting the same payload to replica B's delegation authority is a replay:
    # one signature = one credential = one execution, across processes.
    from actionauth.authority import SignedAuthorizationDetails

    re_signed = SignedAuthorizationDetails(
        command=req.signed_payload["command"],
        args=req.signed_payload["args"],
        rar_type=req.signed_payload["rar_type"],
        exp=req.signed_payload["exp"],
        approver_id=req.signed_payload["approver_id"],
        binding_message=req.signed_payload["binding_message"],
        signature=req.signed_payload["signature"],
    )
    with pytest.raises(SignatureReplay):
        authority_b.mint(re_signed)
    store_b.close()


def test_hitl_expired_session_cannot_be_approved_late(tmp_path) -> None:
    clock = _Clock()
    store, authority, gate = _hitl(tmp_path, clock=clock)
    gate.begin(command="delete-task", args={"task_id": "t-42"},
               caller_id="alice", binding_message="Delete task t-42?")
    sid = consent_session_id(caller_id="alice", command="delete-task",
                             args={"task_id": "t-42"})

    clock.advance(301)  # human returns after the consent window closed

    # Submit is refused by the CAS (expires_at guard).
    assert store.submit_signed(
        sid, demo_sign_as_user(
            command="delete-task", args={"task_id": "t-42"},
            rar_type=RAR_TYPE, approver_id="alice",
            binding_message="Delete task t-42?", user_secret=USER_SECRET,
        ),
    ) is False
    # And resume has nothing to mint.
    assert gate.try_resume(
        command="delete-task", args={"task_id": "t-42"}, caller_id="alice",
    ) is None
