"""End-to-end: parameter-binding property holds through the delegation authority-backed dispatcher.

The publishable property in test form. The dispatcher refuses to execute a
drifted command, and the underlying RS-equivalent (the in-memory store)
is never reached. Replayed credentials are rejected.

Exercised via Tier 1 (InProcessAuthority); the delegation authority-backed integration tests
cover Tier 2 separately. The point of this file is the *zero-unexpected-
RS-calls* property: a wrapped client demonstrates that drift attempts
never reach the underlying executor.
"""
import pytest

from actionauth.core.client import InMemoryTaskStore
from actionauth.core.dispatcher import ApprovalRequired, CommandSuccess, Dispatcher
from actionauth.authority import InProcessAuthority, sign_authorization_details


USER_SECRET = "test-user-secret-32bytes-minimum-pad"
RAR_TYPE = "tasktracker_task_action"


@pytest.fixture
def two_tasks_setup():
    """Fresh client + authority + dispatcher with two pre-seeded tasks."""
    client = InMemoryTaskStore()
    promised = client.create(title="Promised: approved for deletion")
    drifted = client.create(title="Drifted: must survive any drift attempt")
    authority = InProcessAuthority(secret=USER_SECRET, expected_rar_type=RAR_TYPE)
    dispatcher = Dispatcher(client=client, authority=authority)
    return client, authority, dispatcher, promised["task_id"], drifted["task_id"]


def _mint_for_delete(authority, task_id):
    signed = sign_authorization_details(
        command="delete-task",
        args={"task_id": task_id},
        rar_type=RAR_TYPE,
        approver_id="alice",
        binding_message=f"Delete task {task_id}?",
        secret=USER_SECRET,
    )
    return authority.mint(signed)


def test_control_promised_task_deletes(two_tasks_setup):
    client, authority, dispatcher, promised_id, drifted_id = two_tasks_setup
    minted = _mint_for_delete(authority, promised_id)

    outcome = dispatcher.execute("delete-task", {"task_id": promised_id}, approval_token=minted.credential)

    assert isinstance(outcome, CommandSuccess)
    remaining = {t["task_id"] for t in client.list()}
    assert promised_id not in remaining
    assert drifted_id in remaining


def test_drift_attempt_does_not_execute(two_tasks_setup):
    """*** Load-bearing assertion: parameter-binding holds end-to-end. ***"""
    client, authority, dispatcher, promised_id, drifted_id = two_tasks_setup
    minted = _mint_for_delete(authority, promised_id)

    outcome = dispatcher.execute("delete-task", {"task_id": drifted_id}, approval_token=minted.credential)

    assert isinstance(outcome, ApprovalRequired)
    assert outcome.reason == "CredentialDrift"
    remaining = {t["task_id"] for t in client.list()}
    assert promised_id in remaining and drifted_id in remaining


def test_zero_unexpected_rs_calls_property(two_tasks_setup):
    """The 'zero unexpected RS calls' framing.

    Wrap the underlying store and count delete calls. After a drift
    attempt, the count must be 0; the dispatcher must refuse BEFORE
    reaching the executor.
    """
    client, authority, dispatcher, promised_id, drifted_id = two_tasks_setup
    delete_calls: list[str] = []
    original_delete = client.delete

    def counting_delete(task_id: str):
        delete_calls.append(task_id)
        return original_delete(task_id)

    client.delete = counting_delete  # type: ignore[assignment]

    minted = _mint_for_delete(authority, promised_id)

    # Drift attempt must not reach the store.
    _ = dispatcher.execute("delete-task", {"task_id": drifted_id}, approval_token=minted.credential)
    assert delete_calls == [], (
        "store.delete was reached during a drift attempt. "
        "The dispatcher must refuse BEFORE invoking the underlying action."
    )

    # Legitimate path reaches the store exactly once.
    _ = dispatcher.execute("delete-task", {"task_id": promised_id}, approval_token=minted.credential)
    assert delete_calls == [promised_id]


def test_dispatcher_requires_authority_or_rs(two_tasks_setup):
    """``Dispatcher()`` with neither a authority nor an RS is a programming error;
    replaces the old silent fallback to a no-single-use HMAC path."""
    client, _, _, _, _ = two_tasks_setup
    with pytest.raises(ValueError, match="authority.*resource_server"):
        Dispatcher(client=client)


def test_dispatcher_rejects_both_authority_and_rs(two_tasks_setup):
    """Conversely, passing both is also a programming error."""
    client, authority, _, _, _ = two_tasks_setup
    # We can't easily build a real RS here, but a sentinel value triggers
    # the "exactly one" check at construction.
    with pytest.raises(ValueError, match="authority.*resource_server"):
        Dispatcher(client=client, authority=authority, resource_server=object())  # type: ignore[arg-type]
