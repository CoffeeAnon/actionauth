"""Server-side MCP URL-mode elicitation emission + resume (legacy path).

Drives the actual ``build_mcp_app`` MCP server over real HTTP (Starlette
``TestClient``, no transport mock) and asserts the single-agent HITL loop
end to end for **pre-2026 protocol versions**:

  - a HITL-gated ``tools/call`` makes the server emit a URL-mode
    elicitation (``-32042`` / ``URL_ELICITATION_REQUIRED``) pointing at the
    independent consent surface, and
  - after the human approves at that surface, a retried ``tools/call``
    resumes: the bridge mints a delegation authority credential and executes, deleting the
    approved task and leaving the bystander untouched.

The 1.x in-memory harness (``create_connected_server_and_client_session``)
no longer exists in mcp 2.0.0, so this test posts JSON-RPC directly to the
stateless ``/mcp`` surface with the legacy ``mcp-protocol-version:
2025-03-26``. On that surface the SDK sieves ``tools/call`` results against
the legacy ``CallToolResult`` union, which does not include
``InputRequiredResult`` — so the server must (and does) fall back to the
-32042 elicitation error. The 2026 MRTR surface is covered separately in
``test_mcp_stateless_mrtr.py``.

This is the single-agent path - no A2A. The A2A multi-agent carrier is a
separate composition; here the only hop is MCP-host -> consent surface ->
back.
"""
import pytest

pytest.importorskip("mcp")

from starlette.testclient import TestClient  # noqa: E402

from actionauth.audit import AuditSink  # noqa: E402
from actionauth.auth.hmac import TokenStore  # noqa: E402
from actionauth.consent.url_mode import ConsentStore, build_consent_app  # noqa: E402
from actionauth.core.client import InMemoryTaskStore  # noqa: E402
from actionauth.core.dispatcher import Dispatcher  # noqa: E402
from actionauth.mcp.invoker import InProcessInvoker  # noqa: E402
from actionauth.mcp.server import build_mcp_app  # noqa: E402
from actionauth.authority import InProcessAuthority  # noqa: E402

import actionauth.commands  # noqa: F401, E402  (register commands before dispatch)


SECRET = "mcp-elicit-emission-secret-32bytes-pad"
RAR_TYPE = "tasktracker_task_action"
USER_SECRET = SECRET  # demo: consent server signs with the same secret the delegation authority verifies

# Legacy (pre-2026) per-request protocol version: routes the SDK's modern
# dispatch classifier to the legacy surface, where tools/call results are
# sieved against CallToolResult only.
LEGACY_VERSION = "2025-03-26"


def _world(tmp_path):
    audit = AuditSink(str(tmp_path / "audit.db"))
    token_store = TokenStore(str(tmp_path / "tokens.json"))
    store = InMemoryTaskStore()
    target = store.create(title="Q2 launch checklist")
    bystander = store.create(title="Q3 onboarding doc")
    authority = InProcessAuthority(secret=SECRET)
    dispatcher = Dispatcher(client=store, authority=authority)
    invoker = InProcessInvoker(dispatcher)
    consent_store = ConsentStore()
    token = token_store.issue(
        ["tasks.read", "tasks.write"], label="legacy-client", secret=SECRET
    )
    app = build_mcp_app(
        invoker=invoker,
        audit=audit,
        token_store=token_store,
        secret=SECRET,
        consent_store=consent_store,
        authority=authority,
        rar_type=RAR_TYPE,
        bridge_base_url="https://bridge.example",
    )
    return {
        "app": app, "store": store, "consent_store": consent_store,
        "authority": authority, "target": target, "bystander": bystander,
        "token": token,
    }


def _headers(token: str, tool_name: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "mcp-protocol-version": LEGACY_VERSION,
        "mcp-method": "tools/call",
        "mcp-name": tool_name,
    }


def test_hitl_tool_call_emits_url_mode_elicitation(tmp_path):
    w = _world(tmp_path)
    target_id = w["target"]["task_id"]

    with TestClient(w["app"].starlette_app()) as c:
        r = c.post(
            "/mcp",
            headers=_headers(w["token"], "delete_task"),
            json={
                "jsonrpc": "2.0",
                "method": "tools/call",
                "id": 1,
                "params": {"name": "delete_task", "arguments": {"task_id": target_id}},
            },
        )
    assert r.status_code == 200
    err = r.json()["error"]
    assert err["code"] == -32042  # URL_ELICITATION_REQUIRED
    elicitations = err["data"]["elicitations"]
    assert len(elicitations) == 1
    el = elicitations[0]
    assert el["mode"] == "url"
    assert el["url"].endswith(f"/consent/{el['elicitationId']}")
    # The server created a pending consent session for that id.
    assert w["consent_store"].get(el["elicitationId"]) is not None


def test_resume_after_approval_executes_the_approved_action(tmp_path):
    w = _world(tmp_path)
    target_id = w["target"]["task_id"]
    bystander_id = w["bystander"]["task_id"]
    # The human's consent surface, over the SAME store the server emits into.
    consent = TestClient(
        build_consent_app(store=w["consent_store"], user_signing_secret=USER_SECRET)
    )

    with TestClient(w["app"].starlette_app()) as c:
        # 1. First call → URL-mode elicitation; grab the consent session id.
        r1 = c.post(
            "/mcp",
            headers=_headers(w["token"], "delete_task"),
            json={
                "jsonrpc": "2.0",
                "method": "tools/call",
                "id": 1,
                "params": {"name": "delete_task", "arguments": {"task_id": target_id}},
            },
        )
        sid = r1.json()["error"]["data"]["elicitations"][0]["elicitationId"]

        # 2. Human visits the consent page and approves (demo signs server-side).
        assert consent.get(f"/consent/{sid}").status_code == 200
        assert consent.post(
            f"/consent/{sid}/submit", data={"decision": "approve"}
        ).status_code == 200

        # 3. Retry the same call (no MRTR envelope on the legacy surface)
        #    → bridge resumes via the idempotent already-approved branch:
        #    mint (cached) + execute.
        r2 = c.post(
            "/mcp",
            headers=_headers(w["token"], "delete_task"),
            json={
                "jsonrpc": "2.0",
                "method": "tools/call",
                "id": 2,
                "params": {"name": "delete_task", "arguments": {"task_id": target_id}},
            },
        )
        assert r2.status_code == 200
        result = r2.json()["result"]
        assert result.get("resultType", "complete") == "complete"

        # 4. The approved action ran; the bystander was untouched.
        remaining = {t["task_id"] for t in w["store"].list()}
        assert target_id not in remaining
        assert bystander_id in remaining
