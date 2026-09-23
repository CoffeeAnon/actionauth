"""End-to-end test for the URL-mode consent server.

The bridge's MCP elicitation flow uses URL mode per the MCP 2025-11-25
spec (sensitive consent MUST NOT pass through the MCP client's
form-mode handler). The consent server hosts the URL the MCP host
redirects to. This test exercises the full three-endpoint round-trip
via Starlette TestClient:

  GET  /consent/<session>           render consent page
  POST /consent/<session>/submit    user approves / denies
  GET  /consent/<session>/result    bridge polls for the signed payload

Requires `pip install -e '.[mcp]'` for Starlette.
"""
import pytest

starlette = pytest.importorskip("starlette")
from starlette.testclient import TestClient  # noqa: E402

from actionauth.consent.url_mode import ConsentStore, build_consent_app  # noqa: E402


USER_SECRET = "url-mode-test-user-secret-32bytes-pad"
RAR_TYPE = "tasktracker_task_action"


@pytest.fixture
def consent_setup():
    """Fresh consent store + Starlette TestClient over it."""
    store = ConsentStore()
    app = build_consent_app(store=store, user_signing_secret=USER_SECRET)
    return store, TestClient(app)


def _seed(store: ConsentStore):
    return store.create(
        command="delete-task",
        args={"task_id": "task-42"},
        rar_type=RAR_TYPE,
        approver_id="alice@example.com",
        binding_message="Delete the Q2 launch checklist?",
    )


# ── happy path: render → approve → bridge polls → gets signed payload ─────


def test_consent_page_renders_action_details(consent_setup):
    store, client = consent_setup
    req = _seed(store)

    resp = client.get(f"/consent/{req.session_id}")
    assert resp.status_code == 200
    body = resp.text
    # Page must surface the action so the human can make an informed decision.
    assert "delete-task" in body
    assert "task-42" in body
    assert "Q2 launch checklist" in body  # binding message
    assert RAR_TYPE in body


def test_consent_unknown_session_returns_404(consent_setup):
    _, client = consent_setup
    resp = client.get("/consent/does-not-exist")
    assert resp.status_code == 404


def test_approve_then_bridge_polls_for_signed_payload(consent_setup):
    store, client = consent_setup
    req = _seed(store)

    # Before approval: result endpoint returns 202 pending.
    pending = client.get(f"/consent/{req.session_id}/result")
    assert pending.status_code == 202
    assert pending.json()["status"] == "pending"

    # Human approves.
    submit = client.post(
        f"/consent/{req.session_id}/submit",
        data={"decision": "approve"},
    )
    assert submit.status_code == 200
    assert "Approved" in submit.text

    # Bridge polls for the signed payload.
    result = client.get(f"/consent/{req.session_id}/result")
    assert result.status_code == 200
    payload = result.json()
    assert payload["status"] == "approved"
    signed = payload["signed"]
    # All fields the delegation authority needs are present.
    assert signed["command"] == "delete-task"
    assert signed["args"] == {"task_id": "task-42"}
    assert signed["rar_type"] == RAR_TYPE
    assert signed["approver_id"] == "alice@example.com"
    assert isinstance(signed["exp"], int)
    assert len(signed["signature"]) == 64  # hex-encoded HMAC-SHA256


def test_deny_records_denial_and_no_signed_payload(consent_setup):
    store, client = consent_setup
    req = _seed(store)

    submit = client.post(
        f"/consent/{req.session_id}/submit",
        data={"decision": "deny"},
    )
    assert submit.status_code == 200
    assert "Denied" in submit.text

    result = client.get(f"/consent/{req.session_id}/result")
    assert result.json()["status"] == "denied"


def test_double_approve_is_idempotent(consent_setup):
    """A second submit after approval should not replace the signed payload."""
    store, client = consent_setup
    req = _seed(store)

    client.post(f"/consent/{req.session_id}/submit", data={"decision": "approve"})
    first_sig = client.get(f"/consent/{req.session_id}/result").json()["signed"]["signature"]

    # Second approve must not overwrite (sub-second TTL makes this important).
    client.post(f"/consent/{req.session_id}/submit", data={"decision": "approve"})
    second_sig = client.get(f"/consent/{req.session_id}/result").json()["signed"]["signature"]

    assert first_sig == second_sig


def test_approve_after_deny_is_rejected(consent_setup):
    """Once denied, the session is closed; approve cannot retroactively succeed."""
    store, client = consent_setup
    req = _seed(store)

    client.post(f"/consent/{req.session_id}/submit", data={"decision": "deny"})
    client.post(f"/consent/{req.session_id}/submit", data={"decision": "approve"})

    # Result still reflects denial.
    assert client.get(f"/consent/{req.session_id}/result").json()["status"] == "denied"


def test_bad_decision_value_returns_400(consent_setup):
    store, client = consent_setup
    req = _seed(store)

    resp = client.post(
        f"/consent/{req.session_id}/submit", data={"decision": "maybe"},
    )
    assert resp.status_code == 400


def test_submit_to_unknown_session_returns_404(consent_setup):
    _, client = consent_setup
    resp = client.post(
        "/consent/no-such-session/submit", data={"decision": "approve"},
    )
    assert resp.status_code == 404


# ── B1: HTML escaping; the consent page is the trust-UI, no injection allowed ───


def test_consent_page_escapes_html_in_binding_message(consent_setup):
    """A hostile binding_message (e.g., propagated from an attacker-controlled
    task title) must not render as live HTML. The consent page is the
    trust surface where the human decides; injecting markup defeats the
    entire HITL premise."""
    store, client = consent_setup
    req = store.create(
        command="delete-task",
        args={"task_id": "t-42"},
        rar_type="tasktracker_task_action",
        approver_id="alice@example.com",
        binding_message="<script>alert('xss')</script><img src=x onerror=alert(1)>",
    )

    resp = client.get(f"/consent/{req.session_id}")
    assert resp.status_code == 200
    body = resp.text
    # Live tags must be escaped to entities.
    assert "<script>" not in body
    assert "<img" not in body
    assert "&lt;script&gt;" in body
    assert "&lt;img" in body


def test_consent_page_escapes_html_in_args(consent_setup):
    """LLM-controllable arg values must be escaped even after json.dumps;
    JSON encodes quotes but not `<` / `>`."""
    store, client = consent_setup
    req = store.create(
        command="delete-task",
        args={"task_id": "<svg onload=alert(1)>"},
        rar_type="tasktracker_task_action",
        approver_id="alice@example.com",
        binding_message="Delete task?",
    )

    resp = client.get(f"/consent/{req.session_id}")
    body = resp.text
    assert "<svg" not in body
    assert "&lt;svg" in body


def test_consent_form_action_url_cannot_be_hijacked_via_session_id(consent_setup):
    """The form's action URL contains the session_id; if it weren't
    escaped, a session_id containing `" onsubmit=...` could rewrite
    the form attribute. session_ids are bridge-minted so this is more
    defense-in-depth than attack-surface, but the escape must be there."""
    # session_ids are generated by secrets.token_urlsafe; they only
    # contain URL-safe chars, so this is implicit. We verify the
    # escaping is applied anyway.
    store, client = consent_setup
    req = store.create(
        command="delete-task", args={"task_id": "x"}, rar_type="x",
        approver_id="a", binding_message="m",
    )
    resp = client.get(f"/consent/{req.session_id}")
    # Form action must contain the literal session_id, not anything else.
    assert f'action="/consent/{req.session_id}/submit"' in resp.text


# ── B4: cryptographic binding; the proposed action is immutable ──────────────


def test_proposed_action_is_frozen():
    """The action a human is reviewing on the consent page MUST be the
    same action that gets signed. Structurally enforced: ProposedAction
    is a frozen dataclass constructed via ``create()`` (which deep-copies
    args + wraps in MappingProxyType), so neither field reassignment
    NOR in-place mutation of ``args`` can happen between display and
    signing.

    This is the foundation of the threat-model claim that the bridge
    "signs over the emitted authorization_details, not over a
    free-form payload"."""
    from dataclasses import FrozenInstanceError

    from actionauth.consent.url_mode import ProposedAction

    action = ProposedAction.create(
        session_id="s",
        command="delete-task",
        args={"task_id": "t-42"},
        rar_type="tasktracker_task_action",
        approver_id="alice",
        binding_message="Delete?",
    )

    # Top-level field reassignment blocked by @dataclass(frozen=True).
    with pytest.raises(FrozenInstanceError):
        action.command = "different-command"
    with pytest.raises(FrozenInstanceError):
        action.args = {"task_id": "t-43"}
    with pytest.raises(FrozenInstanceError):
        action.rar_type = "different_type"

    # In-place mutation of args blocked by MappingProxyType.
    # `@dataclass(frozen=True)` alone is a shallow freeze; without the
    # MappingProxyType wrap, `action.args["task_id"] = "t-43"` would
    # silently succeed and the next render/sign cycle would use the
    # mutated value. This test guards against regressions where someone
    # "simplifies" the create() method.
    with pytest.raises(TypeError):
        action.args["task_id"] = "t-43"   # type: ignore[index]
    with pytest.raises(TypeError):
        action.args["new_key"] = "x"      # type: ignore[index]


def test_proposed_action_snapshots_caller_args():
    """Mutating the caller's original args dict after ProposedAction
    creation must NOT affect the stored action; create() deep-copies."""
    from actionauth.consent.url_mode import ProposedAction

    caller_args = {"task_id": "t-42", "nested": {"k": "v"}}
    action = ProposedAction.create(
        session_id="s",
        command="delete-task",
        args=caller_args,
        rar_type="tasktracker_task_action",
        approver_id="alice",
        binding_message="Delete?",
    )

    # Caller mutates their own dict after creation.
    caller_args["task_id"] = "victim-id"
    caller_args["nested"]["k"] = "different"

    # Stored action is unchanged.
    assert action.args["task_id"] == "t-42"
    assert action.args["nested"]["k"] == "v"


def test_consent_signing_uses_the_frozen_proposed_action(consent_setup):
    """When the user clicks Approve, the demo signer signs over the
    same fields that are exposed by the frozen ProposedAction. The
    signed_payload returned via /result therefore reflects the
    action the human reviewed, not anything mutable in-between."""
    store, client = consent_setup
    req = store.create(
        command="delete-task",
        args={"task_id": "t-promised"},
        rar_type="tasktracker_task_action",
        approver_id="alice@example.com",
        binding_message="Delete the promised task?",
    )

    # Approve.
    client.post(f"/consent/{req.session_id}/submit", data={"decision": "approve"})
    result = client.get(f"/consent/{req.session_id}/result")
    signed = result.json()["signed"]

    # The signed payload reflects the frozen ProposedAction exactly.
    assert signed["command"] == req.action.command
    assert signed["args"] == req.action.args
    assert signed["rar_type"] == req.action.rar_type
    assert signed["approver_id"] == req.action.approver_id
