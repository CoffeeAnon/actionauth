"""Cross-replica consent atomicity.

The two-instance guarantee this file tests:

  > Two ``DurableConsentStore`` instances pointing at the **same SQLite
  > file**. Instance A: ``create`` + ``submit_signed`` → True. Instance B:
  > ``submit_signed`` on the same session → **False**. The signed payload
  > cannot execute twice.

This file is deliberately self-contained (own clock, own signed-payload
helpers) so the matrix row is readable in one place; the broader durable
consent contracts (TTL window, single-winner CAS, restart durability,
purge semantics, full HITL flow) live in
``tests/unit/test_durable_consent.py``.

The safety invariant: the *database* CAS is the authority, not any
per-process in-memory state. A replica that only trusts its own
connection — or a check-then-set in the store — would let the same
signed approval be submitted (and later executed) twice across replicas,
and this test fails.
"""
from __future__ import annotations

import time

import pytest

pytest.importorskip("mcp")

from actionauth.consent.demo_signer import demo_sign_as_user  # noqa: E402
from actionauth.consent.durable_consent import DurableConsentStore  # noqa: E402

USER_SECRET = "cross-replica-consent-user-secret-32"
RAR_TYPE = "tasktracker_task_action"


class _Clock:
    """Injected clock: starts at the real wall clock and advances without
    sleeping, so both replicas share one notion of time."""

    def __init__(self) -> None:
        self.now = float(time.time())

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


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
    return demo_sign_as_user(user_secret=USER_SECRET, **_action_overrides(**kw))


def test_same_signed_approval_rejected_on_second_replica(tmp_path) -> None:
    """The two-instance test, verbatim contract.

    Both stores are independent connections to ONE sqlite file — the
    deployment shape: two bridge replicas sharing durable state. A
    completes the approval; B presenting the very same signed payload
    must lose the CAS. There is no second approval, hence no second
    execution is possible downstream.
    """
    path = str(tmp_path / "consent.sqlite")
    clock = _Clock()

    a = DurableConsentStore(path, ttl_seconds=300.0, clock=clock)
    b = DurableConsentStore(path, ttl_seconds=300.0, clock=clock)

    # Replica A opens the consent session and the human signs it.
    req = a.create(**_action_overrides(), session_id="mcp-xreplica")
    sid = req.session_id
    signed = _signed()
    assert a.submit_signed(sid, signed) is True

    # Replica B, same file, same session: the identical signed payload
    # cannot be submitted a second time.
    assert b.submit_signed(sid, signed) is False

    # The row carries A's approval and nothing else — B sees the
    # terminal state, not a fresh pending window.
    got = b.get(sid)
    assert got is not None
    assert got.signed_payload is not None
    assert got.signed_payload["approver_id"] == "alice"
    assert got.signed_payload["signature"] == signed["signature"]
    assert got.denied is False

    # Neither can re-open the session: a late deny from B is a no-op,
    # and a second submit from A is a no-op. One approval = one state.
    assert b.deny(sid) is False
    assert a.submit_signed(sid, _signed(approver_id="alice")) is False

    a.close()
    b.close()
